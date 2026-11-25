"""OpenBao client and credential store (docs/openbao-design.md, phase 1).

The host's only secret on disk is its LAN-CA leaf (<host>.<san_domain>). With it the host logs in to OpenBao
(cert auth), uses the short-lived token for one batch of KV v2 calls, and revokes it. Everything else
lives under its own prefix in the KV v2 mount (default `agents`):

  agents/<prefix>/strugglebus-spn      {"secret": <SPN>}           read into memory per spawn, never on disk
  agents/<prefix>/strugglebus          the host identity record    read at start
  agents/<prefix>/workers/<agent>      a worker identity record    while that worker name is in use

`Store` has the same interface as `creds.Store`, so the host does not care which one it holds.

Nothing secret is ever logged or put in an exception: errors carry the HTTP status and a fixed label
only. Every failure raises (OpenBaoError, a subclass of OSError); there is no fallback to a file.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

SEGMENT = re.compile(r"[a-z0-9][a-z0-9-]{0,127}")
SPN_PATH = "strugglebus-spn"
HOST_PATH = "strugglebus"
WORKERS = "workers"

# transport(method, path, token, body) -> (status, parsed JSON or None)
Transport = Callable[[str, str, "str | None", "dict | None"], tuple]


class OpenBaoError(OSError):
    def __init__(self, status: int, what: str):
        super().__init__(f"openbao {what}: {status}")
        self.status = status
        self.what = what


def https_transport(url: str, ca_file: str, cert_file: str, key_file: str, timeout: float = 30) -> Transport:
    """Plain HTTPS with the leaf as the client certificate. The leaf is loaded on each call (step ca renew
    replaces it in place every few hours), so a missing or unreadable leaf fails that call, not the host."""
    base = url.rstrip("/")

    def context() -> ssl.SSLContext:
        for f in (cert_file, key_file):
            if not Path(f).is_file():
                raise OpenBaoError(0, "leaf missing")
        ctx = ssl.create_default_context(cafile=ca_file or None)
        ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
        try:
            ctx.load_cert_chain(cert_file, key_file)
        except (ssl.SSLError, OSError) as e:
            raise OpenBaoError(0, "leaf unreadable") from e
        return ctx

    def call(method: str, path: str, token: str | None, body: dict | None):
        ctx = context()
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            e.read()  # the body may echo the request; it is never kept
            return e.code, None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise OpenBaoError(0, "unreachable") from e

    return call


def _rel(*parts: str) -> str:
    for p in parts:
        if not SEGMENT.fullmatch(p):
            raise ValueError("bad OpenBao path segment")
    return "/".join(parts)


class Session:
    """One login: a token for a batch of calls, revoked on exit (also after an error)."""

    def __init__(self, client: "Client"):
        self.client = client
        self.token: str | None = None

    def __enter__(self) -> "Session":
        c = self.client
        status, body = c.transport("POST", "/v1/auth/cert/login", None, {"name": c.role} if c.role else {})
        token = (body or {}).get("auth", {}).get("client_token") if isinstance(body, dict) else None
        if status != 200 or not isinstance(token, str) or not token:
            raise OpenBaoError(status, "login")
        self.token = token
        return self

    def __exit__(self, *exc) -> None:
        if self.token:
            try:
                self.client.transport("POST", "/v1/auth/token/revoke-self", self.token, None)
            except OSError:
                pass  # the token is short-lived anyway; never mask the real error
            self.token = None

    def _data(self, rel: str) -> str:
        c = self.client
        return f"/v1/{c.mount}/data/{c.prefix}/{rel}"

    def read(self, rel: str) -> dict | None:
        status, body = self.client.transport("GET", self._data(rel), self.token, None)
        if status == 404:
            return None
        data = (body or {}).get("data", {}).get("data") if isinstance(body, dict) else None
        if status != 200 or not isinstance(data, dict):
            raise OpenBaoError(status, "read")
        return data

    def write(self, rel: str, data: dict) -> None:
        status, _ = self.client.transport("POST", self._data(rel), self.token, {"data": data})
        if status not in (200, 204):
            raise OpenBaoError(status, "write")

    def destroy(self, rel: str) -> None:
        """Delete every version and the metadata (KV v2 soft delete would keep them)."""
        c = self.client
        status, _ = c.transport("DELETE", f"/v1/{c.mount}/metadata/{c.prefix}/{rel}", self.token, None)
        if status not in (200, 204, 404):
            raise OpenBaoError(status, "destroy")


class Client:
    def __init__(self, transport: Transport, prefix: str, mount: str = "agents", role: str = ""):
        _rel(prefix)
        _rel(mount)
        self.transport, self.prefix, self.mount, self.role = transport, prefix, mount, role

    def session(self) -> Session:
        return Session(self)

    def health(self) -> bool:
        """Unauthenticated: is OpenBao up, initialised and unsealed? Never raises."""
        try:
            status, _ = self.transport("GET", "/v1/sys/health", None, None)
        except OSError:
            return False
        return status == 200


# --- the leaf certificate (step-ca's HTTP API; no step CLI, so the one-time token is never on a command line) ----
LEAF_CRT, LEAF_KEY, LEAF_CSR = "leaf.crt", "leaf.key", "leaf.csr"
RENEW_BELOW_HOURS = 48.0   # renew hourly, when under 48 h are left


def leaf_not_after(cert_file: Path) -> float | None:
    """The leaf's expiry (epoch seconds), or None if it is missing or unreadable."""
    try:
        info = ssl._ssl._test_decode_cert(str(cert_file))  # noqa: SLF001 - stdlib's own PEM parser
        return ssl.cert_time_to_seconds(info["notAfter"])
    except (OSError, ValueError, KeyError, ssl.SSLError):
        return None


def leaf_san(cert_file: Path) -> list[str]:
    try:
        info = ssl._ssl._test_decode_cert(str(cert_file))  # noqa: SLF001
    except (OSError, ValueError, ssl.SSLError):
        return []
    return [v for k, v in info.get("subjectAltName", ()) if k == "DNS"]


def _ca_post(ca_url: str, ca_file: str, path: str, body: dict, cert: tuple[str, str] | None = None,
             timeout: float = 30) -> dict:
    ctx = ssl.create_default_context(cafile=ca_file or None)
    ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    if cert:
        try:
            ctx.load_cert_chain(*cert)
        except (ssl.SSLError, OSError) as e:
            raise OpenBaoError(0, "leaf unreadable") from e
    req = urllib.request.Request(ca_url.rstrip("/") + path, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            out = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        e.read()
        raise OpenBaoError(e.code, "ca " + path.rsplit("/", 1)[-1]) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise OpenBaoError(0, "ca unreachable") from e
    if not isinstance(out, dict):
        raise OpenBaoError(0, "ca answer")
    return out


def _chain(out: dict) -> str:
    """The leaf followed by its intermediate(s), as step-ca returns them."""
    certs = out.get("certChain") or [c for c in (out.get("crt"), out.get("ca")) if c]
    if not certs or not all(isinstance(c, str) and "BEGIN CERTIFICATE" in c for c in certs):
        raise OpenBaoError(0, "ca answer")
    return "".join(c if c.endswith("\n") else c + "\n" for c in certs)


def sign_leaf(ca_url: str, ca_file: str, csr_pem: str, token: str, not_after: str = "72h") -> str:
    """First issue: the CSR and the one-time token (in the request body, over the pinned TLS) -> the chain PEM."""
    return _chain(_ca_post(ca_url, ca_file, "/1.0/sign", {"csr": csr_pem, "ott": token, "notAfter": not_after}))


def renew_leaf(ca_url: str, ca_file: str, leaf_dir: Path) -> str:
    """Renewal authenticates with the current leaf (mTLS); the key stays, the CA keeps the validity length."""
    return _chain(_ca_post(ca_url, ca_file, "/1.0/renew", {},
                           cert=(str(leaf_dir / LEAF_CRT), str(leaf_dir / LEAF_KEY))))


def write_leaf(leaf_dir: Path, chain_pem: str) -> None:
    from . import creds  # owner_only (icacls on Windows)

    leaf_dir.mkdir(parents=True, exist_ok=True)
    tmp = leaf_dir / (LEAF_CRT + ".tmp")
    tmp.write_text(chain_pem, encoding="ascii")
    creds.owner_only(tmp)
    os.replace(tmp, leaf_dir / LEAF_CRT)


class Store:
    """creds.Store's interface over OpenBao. Each call is its own login, read or write, and revoke."""

    def __init__(self, client: Client, host_agent: str):
        self.client = client
        self.host_agent = host_agent

    def _path(self, agent: str) -> str:
        if agent == self.host_agent:
            return HOST_PATH
        return _rel(WORKERS, agent)

    # SPN
    def save_spn(self, secret: str, rotated_at: float | None = None) -> None:
        data = {"secret": secret.strip()}
        if rotated_at is not None:
            data["rotated_at"] = str(int(rotated_at))
        with self.client.session() as s:
            s.write(SPN_PATH, data)

    def spn_rotated_at(self) -> float | None:
        """When the SPN was last rotated (or its rotation clock started), or None if never recorded."""
        with self.client.session() as s:
            data = s.read(SPN_PATH) or {}
        try:
            return float(data["rotated_at"])
        except (KeyError, TypeError, ValueError):
            return None

    def load_spn(self) -> str:
        with self.client.session() as s:
            data = s.read(SPN_PATH)
        secret = (data or {}).get("secret")
        if not isinstance(secret, str) or not secret:
            raise LookupError("no SPN credential in OpenBao")
        return secret

    def has_spn(self) -> bool:
        with self.client.session() as s:
            return s.read(SPN_PATH) is not None

    # identities
    def has(self, agent: str) -> bool:
        with self.client.session() as s:
            return s.read(self._path(agent)) is not None

    def save(self, agent: str, record: dict) -> None:
        with self.client.session() as s:
            s.write(self._path(agent), dict(record))

    def load(self, agent: str) -> dict:
        with self.client.session() as s:
            data = s.read(self._path(agent))
        if data is None:
            raise LookupError(f"no credential stored for {agent}")
        return data

    def remove(self, agent: str) -> None:
        with self.client.session() as s:
            s.destroy(self._path(agent))
