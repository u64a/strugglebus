"""Strugglebus client: a port of the vault's tooling/bus.py that keeps credentials in the DPAPI store.

Workers call it exactly as they call bus.py today:

  python busclient.py post <agent> <channel> <kind> <text...>
  python busclient.py read <agent> <channel> [since] [limit]
  python busclient.py whoami <agent>
  python busclient.py notes <agent>

SB_BUS_STORE names the DPAPI store folder (the host sets it for its workers), SB_BUS_CA the bus CA file,
SB_BUS_URL the bus. The credential is decrypted by agent name. Secrets never print: errors show the HTTP status
and a redacted, truncated detail only.

`notes` is read-only: it prints the coordinator's notes to this worker since its task was posted.
A note is a message on the task's notes channel (SB_NOTES_CHANNEL: the coordinator's notes_channel in
fleet.toml, always set by the host), with seq greater than SB_TASK_SEQ, whose bus-authenticated
sender is the coordinator that sent the task (SB_COORDINATOR_ID and SB_COORDINATOR_NAME, both must
match), and whose body starts with a mention of the worker's full agent name (`@<agent>`, alone or among
other leading mentions). The host sets these variables for each worker it starts.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from workerhost import creds  # noqa: E402
    from workerhost.redact import redact  # noqa: E402
else:
    from . import creds
    from .redact import redact

KINDS = ("announce", "question", "answer", "status", "chat")


class BusError(Exception):
    def __init__(self, status: int, what: str, detail: str = ""):
        super().__init__(f"{what}: {status}")
        self.status = status
        self.detail = detail  # the bus's own short "detail" text, already checked by server_detail()


def server_detail(body, *never: str) -> str:
    """The bus's error text when it is a short plain string ({"detail": "..."}), else "".

    Only the server's own string is kept, never a structured echo of the request, and it is dropped
    if it contains any of `never` (the credential that was sent)."""
    detail = body.get("detail") if isinstance(body, dict) else None
    if not isinstance(detail, str) or not 0 < len(detail) <= 120 or not detail.isprintable():
        return ""
    if any(s and s in detail for s in never) or redact(detail) != detail:
        return ""
    return detail


class Bus:
    def __init__(self, base: str, ca_file: str, token: str | None = None, timeout: float = 30):
        self.base = base.rstrip("/")
        self.ca_file = ca_file
        self.token = token
        self.timeout = timeout

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.ca_file or None)
        ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
        return ctx

    def call(self, method: str, path: str, *, body: dict | None = None, query: dict | None = None,
             token: str | None = None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        tok = token or self.token
        if tok:
            headers["Authorization"] = "Bearer " + tok
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._context()) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode("utf-8", "replace")[:300]

    # messages ------------------------------------------------------------------------------------
    def post(self, channel: str, kind: str, text: str, reply_to: int | None = None,
             metadata: dict | None = None) -> int:
        if kind not in KINDS:
            raise ValueError("unknown kind")
        body = {"body": text, "kind": kind, "request_id": str(uuid.uuid4())}
        if reply_to:
            body["reply_to"] = int(reply_to)
        if metadata:
            body["metadata"] = metadata  # structured data beside the text (the bus caps it at 16 KB)
        status, msg = self.call("POST", f"/api/channels/{urllib.parse.quote(channel, safe='')}/messages", body=body)
        if status != 201 or not isinstance(msg, dict) or not isinstance(msg.get("seq"), int):
            raise BusError(status, "post")
        return msg["seq"]

    def read(self, channel: str, since: int = 0, limit: int = 100) -> list[dict]:
        status, msgs = self.call("GET", f"/api/channels/{urllib.parse.quote(channel, safe='')}/messages",
                                 query={"since": since, "limit": limit})
        if status != 200 or not isinstance(msgs, list):
            raise BusError(status, "read")
        return [m for m in msgs if isinstance(m, dict) and isinstance(m.get("seq"), int)]

    def read_all(self, channel: str, since: int, page: int = 200, max_pages: int = 50) -> list[dict]:
        out: list[dict] = []
        cursor = since
        for _ in range(max_pages):
            batch = self.read(channel, cursor, page)
            out.extend(batch)
            if len(batch) < page:
                break
            cursor = max(m["seq"] for m in batch)
        return out

    def newest_seq(self, channel: str) -> int:
        latest = 0
        while True:
            batch = self.read(channel, latest, 200)
            if not batch:
                return latest
            latest = max(latest, max(m["seq"] for m in batch))
            if len(batch) < 200:
                return latest

    def whoami(self) -> dict:
        status, body = self.call("GET", "/api/whoami")
        if status != 200 or not isinstance(body, dict):
            raise BusError(status, "whoami")
        return body


def _detail(body) -> str:
    text = body if isinstance(body, str) else json.dumps(body)
    return redact(text)[:200]


def onboard(bus: Bus, spn_secret: str, agent: str, description: str, identity_ttl_seconds: int | None = None) -> dict:
    """SPN -> onboarding package -> redeem. Returns the identity record (holds the secret; never print it).
    identity_ttl_seconds (bus 0.2.61): the identity expires terminally then and the bus retires it; None is a
    durable identity, as before."""
    req = {"request_id": str(uuid.uuid4()), "agent_name": agent, "description": description}
    if identity_ttl_seconds is not None:
        req["identity_ttl_seconds"] = int(identity_ttl_seconds)
    status, envelope = bus.call("POST", "/api/spn/onboarding-packages", token=spn_secret, body=req)
    if status not in (200, 201) or not isinstance(envelope, dict):
        raise BusError(status, "onboarding package refused", server_detail(envelope, spn_secret))
    package = dict(envelope.get("package") or envelope)
    token_key = next(iter(sorted(k for k, v in package.items()
                                 if isinstance(v, str) and v.startswith(("sbse1_", "sbsa1_")))), None)
    token = package.get(token_key) if token_key else package.get("enrollment_token")
    if not token:
        raise BusError(0, "package carries no enrollment token")
    redeem_path = package.get("redeem_path") or "/api/enrollments/redeem"
    if not isinstance(redeem_path, str) or not redeem_path.startswith("/api/"):
        raise BusError(0, "unexpected redeem path")
    status, redeemed = bus.call("POST", redeem_path, token=token,
                                body={"request_id": str(uuid.uuid4()), "name": agent,
                                      "host": os.environ.get("COMPUTERNAME", ""), "description": description})
    if status not in (200, 201) or not isinstance(redeemed, dict):
        raise BusError(status, "redeem refused")
    record = {
        "agent_id": redeemed["agent"]["id"], "agent_name": redeemed["agent"]["name"],
        "credential_id": redeemed["credential"]["id"],
        "credential_version": redeemed["credential"].get("version", 0),
        "credential_epoch": redeemed["agent"].get("credential_epoch", 0),
        "secret": redeemed["credential_secret"], "base_url": bus.base,
    }
    expires = package.get("identity_expires_at") or redeemed["agent"].get("identity_expires_at")
    if isinstance(expires, str):
        record["identity_expires_at"] = expires
    return record


def rotate_spn(bus: Bus, spn_secret: str, request_id: str) -> str | None:
    """SPN self-rotation (bus 0.2.61): 201 returns the successor exactly once; the predecessor keeps working for
    60 s. A replay of the same request_id returns 200 with no secret (None). Raises BusError otherwise."""
    status, body = bus.call("POST", "/api/spn/credentials/rotate", token=spn_secret, body={"request_id": request_id})
    if status == 200:
        return None
    if status != 201 or not isinstance(body, dict):
        raise BusError(status, "spn rotate", server_detail(body, spn_secret))
    found = [v for v in (body.get("credential_secret"), (body.get("credential") or {}).get("secret")
                         if isinstance(body.get("credential"), dict) else None, *body.values())
             if isinstance(v, str) and v.startswith("sbsp1_") and v != spn_secret]
    if not found:
        raise BusError(0, "spn rotate: no successor in the answer")
    return found[0]


def retire(bus: Bus, spn_secret: str, agent: str) -> int:
    """SPN retire of an identity it created (bus 0.2.61). Idempotent; 200 retired (or already), 404 unknown or not
    this SPN's. Returns the HTTP status."""
    status, _ = bus.call("POST", f"/api/spn/agents/{urllib.parse.quote(agent, safe='')}/retire", token=spn_secret,
                         body={"request_id": str(uuid.uuid4())})
    return status


def bootstrap(bus: Bus, record: dict, channels: tuple[str, ...]) -> list[str]:
    """whoami -> prove if pending -> RoE acknowledge -> subscribe. Returns notes safe to log."""
    notes = []
    me = bus.whoami()
    if me["agent"]["id"] != record["agent_id"] or me["agent"]["name"] != record["agent_name"]:
        raise BusError(0, "identity mismatch")
    cred = me["credential"]
    if cred.get("status") == "pending":
        status, _ = bus.call("POST", "/api/credentials/prove", body={
            "request_id": str(uuid.uuid4()), "expected_agent_id": record["agent_id"],
            "expected_agent_name": record["agent_name"], "expected_credential_version": cred.get("version", 0),
            "expected_credential_epoch": me["agent"].get("credential_epoch", 0)})
        notes.append(f"prove {status}")
    status, roe = bus.call("GET", "/api/roe/effective")
    if status != 200 or not isinstance(roe, dict):
        raise BusError(status, "roe")
    if roe.get("receipt_status") != "current":
        ack = {"global_revision_id": roe["global_revision"]["id"],
               "global_content_sha256": roe["global_revision"]["content_sha256"],
               "effective_sha256": roe["effective_sha256"]}
        if roe.get("agent_revision"):
            ack["agent_revision_id"] = roe["agent_revision"]["id"]
            ack["agent_content_sha256"] = roe["agent_revision"]["content_sha256"]
        status, _ = bus.call("POST", "/api/roe/acknowledgements", body=ack)
        notes.append(f"roe ack {status}")
    for channel in channels:
        status, _ = bus.call("PUT", f"/api/subscriptions/{urllib.parse.quote(channel, safe='')}")
        notes.append(f"subscribe {channel} {status}")
    return notes


# --- checkpoint notes ----------------------------------------------------------------------------
_NAME = r"[A-Za-z0-9_-]"
_LEADING_MENTIONS = re.compile(r"\s*((?:@" + _NAME + r"+[\s,;:]*)+)")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def addressed_to(body: str, agent: str) -> bool:
    """The body opens with mentions (`@a @b ...`) and one of them is exactly @<agent>."""
    m = _LEADING_MENTIONS.match(body)
    return bool(m) and agent in re.findall(r"@(" + _NAME + r"+)", m.group(1))


def names(body: str, agent: str) -> bool:
    return re.search(r"(?<!" + _NAME + r")" + re.escape(agent) + r"(?!" + _NAME + r")", body) is not None


def select_notes(messages: list[dict], agent: str, since: int, coordinator_id: str,
                 coordinator_name: str, also: tuple[str, ...] = ()) -> tuple[list[dict], int, int]:
    """(notes oldest first, ignored from another sender, ignored that only name the worker).

    Only messages after `since` that address or name the worker are looked at; the worker's own posts
    are skipped. The sender is the bus-authenticated agent_id AND agent_name, never the body."""
    # `also`: the worker name's stable bus name (<prefix>-<worker>) when the worker posts as a per-task identity
    # (phase 2): coordinators address notes to the stable name, as the coordinator guide says.
    aliases = (agent, *[a for a in also if a and a != agent])
    notes: list[dict] = []
    other = quoted = 0
    seen: set[int] = set()
    for m in sorted(messages, key=lambda x: x["seq"]):
        if m["seq"] <= since or m["seq"] in seen or m.get("agent_name") in aliases:
            continue
        seen.add(m["seq"])
        body = m.get("body")
        body = body if isinstance(body, str) else json.dumps(body)
        if not any(names(body, a) for a in aliases):
            continue
        from_coordinator = (bool(coordinator_id) and m.get("agent_id") == coordinator_id
                            and m.get("agent_name") == coordinator_name)
        if not from_coordinator:
            other += 1
        elif any(addressed_to(body, a) for a in aliases):
            notes.append({"seq": m["seq"], "kind": m.get("kind"), "created_at": m.get("created_at"), "body": body})
        else:
            quoted += 1
    return notes, other, quoted


def _count(n: int, what: str) -> str:
    return f"{n} message{'' if n == 1 else 's'} {what} ignored"


def format_notes(notes: list[dict], other: int, quoted: int) -> list[str]:
    lines = [f"note seq={n['seq']} ({n.get('kind')}, {str(n.get('created_at'))[:19]}): {n['body']}" for n in notes]
    if not notes:
        lines.append("no notes")
    if other:
        lines.append(_count(other, "from another sender"))
    if quoted:
        lines.append(_count(quoted, "that only quote this worker's name"))
    return lines


_CHANNEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def setting(name: str, env=None, default: str = "") -> str:
    """SB_<name>, else `default`."""
    env = os.environ if env is None else env
    return env.get("SB_" + name) or default


def notes_settings(env=None) -> tuple[int, str, str, str]:
    """(task seq, coordinator agent_id, coordinator name, notes channel) as the host set them, or ValueError."""
    seq = setting("TASK_SEQ", env)
    coord_id = setting("COORDINATOR_ID", env)
    coord_name = setting("COORDINATOR_NAME", env)
    channel = setting("NOTES_CHANNEL", env)  # no default: the host sets the sending coordinator's own channel
    if not seq.isdigit() or int(seq) <= 0:
        raise ValueError("SB_TASK_SEQ is not set by the host")
    if not _UUID.fullmatch(coord_id) or not coord_name:
        raise ValueError("the coordinator pin is not set by the host")
    if not _CHANNEL.fullmatch(channel):
        raise ValueError("SB_NOTES_CHANNEL is not set by the host, or is not a channel name")
    return int(seq), coord_id, coord_name, channel


def read_notes(bus: Bus, agent: str, env=None, page: int = 200, max_pages: int = 500) -> list[str]:
    since, coord_id, coord_name, channel = notes_settings(env)
    messages: list[dict] = []
    cursor = since
    for _ in range(max_pages):
        batch = bus.read(channel, cursor, page)
        messages.extend(batch)
        if len(batch) < page:
            also = (setting("NOTES_NAME", env),)
            return format_notes(*select_notes(messages, agent, since, coord_id, coord_name, also))
        cursor = max(m["seq"] for m in batch)
    raise ValueError(f"too many {channel} messages since the task; notes not read")


def client_for(agent: str, store_dir: str | None = None, env=None) -> Bus:
    """SB_BUS_TOKEN (set by a host using OpenBao) wins and is the only source then: no store is looked at.
    Otherwise the DPAPI store named by SB_BUS_STORE, decrypted by agent name. Neither set: LookupError."""
    env = os.environ if env is None else env
    token = env.get("SB_BUS_TOKEN")
    if token:
        base = setting("BUS_URL", env)
        if not base:
            raise LookupError("no bus address: SB_BUS_URL is not set")
        return Bus(base, setting("BUS_CA", env), token)
    folder = store_dir or setting("BUS_STORE", env)
    if not folder:
        raise LookupError("no bus credential: neither SB_BUS_TOKEN nor SB_BUS_STORE is set")
    rec = creds.Store(Path(folder)).load(agent)
    base = setting("BUS_URL", env) or rec.get("base_url")  # the identity record names the bus it was made on
    if not base:
        raise LookupError("no bus address: SB_BUS_URL is not set and the identity record names none")
    return Bus(base, setting("BUS_CA", env), rec["secret"])


def main(argv: list[str]) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(argv) < 2 or argv[0] not in ("post", "read", "whoami", "notes"):
        print(__doc__)
        return 2
    cmd, agent, *rest = argv
    if cmd == "notes":
        try:
            notes_settings()
        except ValueError as e:
            print(f"notes failed: {e}")
            return 1
    try:
        bus = client_for(agent)
        if cmd == "notes":
            try:
                lines = read_notes(bus, agent)
            except ValueError as e:
                print(f"notes failed: {e}")
                return 1
            for line in lines:
                print(line)
        elif cmd == "post":
            if len(rest) < 3:
                print("usage: post <agent> <channel> <kind> <text...>")
                return 2
            seq = bus.post(rest[0], rest[1], " ".join(rest[2:]))
            print(f"post: 201 seq={seq}")
        elif cmd == "read":
            since = int(rest[1]) if len(rest) > 1 else 0
            limit = int(rest[2]) if len(rest) > 2 else 50
            for m in bus.read(rest[0], since, limit):
                re_ = f", re {m['reply_to']}" if m.get("reply_to") else ""
                print(f"[{m['seq']}] {str(m.get('created_at'))[:19]} {m.get('agent_name')} ({m.get('kind')}{re_}): "
                      f"{m.get('body')}")
        else:
            me = bus.whoami()
            print(json.dumps({"agent": me.get("agent", {}).get("name"), "id": me.get("agent", {}).get("id")}))
    except BusError as e:
        print(f"{cmd} failed: {e.status}")
        return 1
    except (LookupError, KeyError, OSError, ValueError) as e:
        print(f"{cmd} failed: {type(e).__name__}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
