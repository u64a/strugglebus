r"""Checking the owner's signatures on fleet.toml (and later baseline.toml and releases): docs/signing-keys.md.

A signed file comes with an SSH signature (`ssh-keygen -Y sign`) made with a pinned key (a hardware key such as a YubiKey). The
host checks it with `ssh-keygen -Y verify` against the public keys pinned at setup in
C:\ProgramData\strugglebus\allowed_signers. Only an elevated prompt can write there; the host and its workers
run without elevation, so nothing the host runs can add a key.

What this protects against: a change pushed to GitHub by anything other than the signer (an agent holding their token,
a stolen token). It does not protect against code running as the host's own Windows user, which could change
the host itself; that is what the security standard and running unelevated are for.

The signed bytes are fed to ssh-keygen on stdin and the signature is written to a private temp file, so no
path from the repository ever reaches a command line.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

NS_FLEET = "strugglebus-fleet"
NS_BASELINE = "strugglebus-baseline"
NS_RELEASE = "strugglebus-release"
MAX_SIG_BYTES = 16 * 1024
SIG_HEADER = b"-----BEGIN SSH SIGNATURE-----"

# Win32-OpenSSH from winget first (the one the runbooks use), then the one built into Windows, then Git's.
# All three verify the same way (checked 4 Nov 2026: 10.0p2, 9.5p2 and Git 2.54's).
KEYGEN_CANDIDATES = (
    r"C:\Program Files\OpenSSH\ssh-keygen.exe",
    os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "OpenSSH", "ssh-keygen.exe"),
    r"C:\Program Files\Git\usr\bin\ssh-keygen.exe",
)
KEY_TYPES = {"ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa"}


def pinned_path() -> Path:
    """C:\\ProgramData\\strugglebus\\allowed_signers: admin-write only, pinned by install.ps1 -PinSigners."""
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "strugglebus" / "allowed_signers"


def find_ssh_keygen(configured: str = "") -> str | None:
    """An absolute path to ssh-keygen, never a bare name looked up on PATH."""
    for candidate in ((configured,) if configured else KEYGEN_CANDIDATES):
        if candidate and os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
    return None


@dataclass(frozen=True)
class Signer:
    principal: str
    namespaces: str
    key_type: str
    fingerprint: str
    comment: str


def fingerprint(key_type: str, blob_b64: str) -> str:
    """The SHA256:... fingerprint ssh-keygen -lf prints, computed from the key itself."""
    raw = base64.b64decode(blob_b64, validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def read_signers(path: Path) -> list[Signer]:
    """The pinned list as (principal, namespaces, key type, fingerprint, comment). Unparseable lines are skipped
    here; ssh-keygen is what decides, this is for showing what a host trusts."""
    out = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        tokens = line.split()
        if not tokens or tokens[0].startswith("#"):
            continue
        idx = next((i for i, t in enumerate(tokens) if t in KEY_TYPES), None)
        if idx is None or idx + 1 >= len(tokens):
            continue
        found = re.search(r'(?:^|,)namespaces="([^"]*)"', " ".join(tokens[1:idx]))
        namespaces = found.group(1) if found else ""
        try:
            fp = fingerprint(tokens[idx], tokens[idx + 1])
        except (ValueError, binascii.Error):
            continue
        out.append(Signer(tokens[0], namespaces, tokens[idx], fp, " ".join(tokens[idx + 2:])))
    return out


@dataclass(frozen=True)
class Verified:
    ok: bool
    reason: str  # "good", or why not: no-signers, no-ssh-keygen, sig-shape, bad-signature, ssh-keygen-failed,
    #              sk-no-pin (a security key signed without both the touch and the PIN)
    fingerprint: str = ""
    principal: str = ""  # who signed: the allowed_signers principal whose key verified it


PRINCIPAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")


def principals_for(path: Path, namespace: str) -> list[str]:
    """The principals in the pinned list that may sign in `namespace` (a line with no namespaces= may sign in any),
    in file order, each once. Any of them is trusted: being in the admin-written list is what trusts a key."""
    out: list[str] = []
    for s in read_signers(path):
        allowed = not s.namespaces or namespace in s.namespaces.split(",")
        for p in s.principal.split(","):
            if allowed and PRINCIPAL_RE.fullmatch(p) and p not in out:
                out.append(p)
    return out


def verify(data: bytes, sig: bytes, namespace: str, allowed_signers: Path, ssh_keygen: str | None,
           workdir: Path) -> Verified:
    """Is `sig` a good signature over exactly `data`, in `namespace`, by a key in `allowed_signers`? ssh-keygen
    checks it against each principal that may sign in the namespace until one verifies."""
    if not allowed_signers.is_file():
        return Verified(False, "no-signers")
    if not ssh_keygen:
        return Verified(False, "no-ssh-keygen")
    if not sig.startswith(SIG_HEADER) or len(sig) > MAX_SIG_BYTES:
        return Verified(False, "sig-shape")
    principals = principals_for(allowed_signers, namespace)
    if not principals:
        return Verified(False, "no-signers")
    workdir.mkdir(parents=True, exist_ok=True)
    stem = workdir / f"verify-{uuid.uuid4().hex}"
    sig_file, data_file = stem.with_suffix(".sig"), stem.with_suffix(".data")
    try:
        sig_file.write_bytes(sig)
        data_file.write_bytes(data)
        for principal in principals:
            out = _verify_as(ssh_keygen, allowed_signers, principal, namespace, sig_file, data_file)
            if out is not None:
                fp = next((t for t in out.split() if t.startswith("SHA256:")), "")
                if not touch_and_pin(sig):
                    return Verified(False, "sk-no-pin", fp, principal)
                return Verified(True, "good", fp, principal)
    except (OSError, subprocess.TimeoutExpired):
        return Verified(False, "ssh-keygen-failed")
    finally:
        for f in (sig_file, data_file):
            try:
                f.unlink()
            except OSError:
                pass
    return Verified(False, "bad-signature")


# A security key's signature carries the authenticator's flags, and they are inside what it signs:
# 0x01 the user touched it, 0x04 the user was verified (the PIN). ssh-keygen -Y verify requires the touch but has no
# way to require the PIN: OpenSSH's allowed_signers takes no verify-required option ("unknown key option", Windows'
# OpenSSH 10.0, tested 27 Nov 2026). So the host checks the flags itself, after ssh-keygen has verified the
# signature (which is what makes the flags genuine). Every release and fleet signature made so far carries 0x05.
SK_TOUCH, SK_PIN = 0x01, 0x04


def sk_flags(sig: bytes) -> int | None:
    """The flags byte of a security-key SSHSIG signature, None for any other key type. Raises ValueError on a
    signature it can't take apart."""
    lines = sig.decode("ascii").strip().splitlines()
    blob = base64.b64decode("".join(line for line in lines if not line.startswith("-----")), validate=True)

    def field(buf: bytes, i: int) -> tuple[bytes, int]:
        if i + 4 > len(buf):
            raise ValueError("short")
        n = int.from_bytes(buf[i:i + 4], "big")
        if i + 4 + n > len(buf):
            raise ValueError("short")
        return buf[i + 4:i + 4 + n], i + 4 + n

    if blob[:6] != b"SSHSIG":
        raise ValueError("not SSHSIG")
    i = 10  # magic and version
    for _ in range(4):  # public key, namespace, reserved, hash algorithm
        _, i = field(blob, i)
    inner, _ = field(blob, i)
    sig_type, j = field(inner, 0)
    if not sig_type.startswith(b"sk-"):
        return None
    _, j = field(inner, j)  # the signature itself
    if j >= len(inner):
        raise ValueError("no flags")
    return inner[j]


def touch_and_pin(sig: bytes) -> bool:
    """True unless a security key signed without both the touch and the PIN."""
    try:
        flags = sk_flags(sig)
    except (ValueError, UnicodeDecodeError):
        return False
    return flags is None or flags & (SK_TOUCH | SK_PIN) == SK_TOUCH | SK_PIN


def _verify_as(ssh_keygen: str, allowed_signers: Path, principal: str, namespace: str, sig_file: Path,
               data_file: Path) -> str | None:
    """ssh-keygen's "Good ... signature" line if the signature verifies for `principal`, else None."""
    # The signed bytes go in as a FILE on stdin, never a pipe: Windows' own ssh-keygen (9.5) never finishes
    # reading a piped stdin when the caller runs in an SSH session (a `wh fleet status` over SSH timed out
    # and called a good fleet unavailable). A file handle is what `ssh-keygen ... < fleet.toml` gives it.
    with open(data_file, "rb") as stdin:
        r = subprocess.run([ssh_keygen, "-Y", "verify", "-f", str(allowed_signers), "-I", principal,
                            "-n", namespace, "-s", str(sig_file)], stdin=stdin, capture_output=True, timeout=60)
    out = r.stdout.decode("utf-8", "replace").strip()
    good = f'Good "{namespace}" signature for {principal} with '
    return out if r.returncode == 0 and out.startswith(good) else None
