"""Enrol a new host with the App's one-time code (docs/app-host-integration.md section 2.2 step 8).

The bus mints a single-use host enrolment code bound to one prefix (`host-<hostname>`). The host redeems it for its
own service principal credential, then onboards `<prefix>-host` with the existing SPN calls. The code and the
credential are never printed, logged or put on a command line: the code comes in on stdin, the credential goes
straight to the store.

Wire shapes (as the bus implements it):
    POST /api/hosts/enrollments/redeem
        Authorization: Bearer sbhe1_<22>_<43>        (the code, as every other bus enrolment code)
        body {"request_id": "<canonical lowercase UUID>"}
    201 first redeem / 200 the same request_id again: {"name", "credential", "request_id"}. A replay issues a NEW
        credential and revokes the earlier one (the bus keeps only hashes), so the latest answer is the one stored.
        It works until the code expires (15 minutes at most), and not once the service principal is blocked.
    The host keys off the STATUS only: 401 (no or ill-shaped code) and 404 (wrong, used or replaced code) -> ask for a
    new script; 410 expired; 409 name-taken; 422 malformed (a bootstrap bug); 429 rate limited; 503 frozen or cannot
    store (the code is not burned).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from .busclient import Bus

REDEEM_PATH = "/api/hosts/enrollments/redeem"
CODE_RE = re.compile(r"sbhe1_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
STATE_FILE = "enrol.json"
ATTEMPTS = 3

MESSAGES = {  # fixed texts: nothing from the bus is ever printed
    "bad-code": "that is not a host enrolment code (sbhe1_...); nothing sent",
    "unknown-or-used-code": "the code is wrong or already used: ask the App for a new script",
    "expired": "the code has expired (15 minutes): ask the App for a new script",
    "name-taken": "that host name already has an enrolled service principal: retire it in the App, or pick another name",
    "bad-request": "the bus did not accept the request's shape (a bootstrap bug): stopping",
    "unavailable": "the bus cannot accept enrolments right now (agent access frozen, or busy); the code is not used up: "
                   "try again later",
    "rate-limited": "the bus is limiting enrolment attempts: wait a few minutes and run it again",
    "wrong-name": "the bus returned a credential for a different host name: refusing it",
    "bad-reply": "the bus's reply was not the expected shape: refusing it",
    "unexpected": "the bus gave an unexpected answer",
}
STATUS_CODES = {400: "bad-request", 401: "unknown-or-used-code", 404: "unknown-or-used-code", 409: "name-taken",
                410: "expired", 422: "bad-request", 429: "rate-limited", 503: "unavailable"}


class EnrolError(Exception):
    def __init__(self, code: str, status: int = 0):
        super().__init__(MESSAGES[code] + (f" (HTTP {status})" if status else ""))
        self.code, self.status = code, status


def request_id(state_dir: Path) -> str:
    """The request id for this host's redeem, made once and kept, so a retry after a dropped connection reuses it
    (the bus then answers the same instead of treating it as a second use of the code)."""
    path = Path(state_dir) / STATE_FILE
    try:
        rid = json.loads(path.read_text(encoding="utf-8")).get("request_id", "")
        if UUID_RE.fullmatch(rid):
            return rid
    except (OSError, ValueError, AttributeError):
        pass
    rid = str(uuid.uuid4())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"request_id": rid}) + "\n", encoding="utf-8")
    return rid


def _secret_from(body, prefix: str, rid: str) -> str:
    if not isinstance(body, dict):
        raise EnrolError("bad-reply")
    if body.get("name") != prefix:
        raise EnrolError("wrong-name")
    if body.get("request_id") != rid:
        raise EnrolError("bad-reply")
    secret = body.get("credential")
    if not isinstance(secret, str) or not secret.startswith("sbsp1_") or len(secret) < 20:
        raise EnrolError("bad-reply")
    return secret


def redeem(bus: Bus, code: str, rid: str, prefix: str, sleep=time.sleep) -> str:
    """The SPN credential for `prefix`, or EnrolError. Retries only a rate limit (twice, with a pause)."""
    if not CODE_RE.fullmatch(code):
        raise EnrolError("bad-code")
    for attempt in range(ATTEMPTS):
        status, body = bus.call("POST", REDEEM_PATH, body={"request_id": rid}, token=code)
        if status in (200, 201):
            return _secret_from(body, prefix, rid)
        if status == 429 and attempt < ATTEMPTS - 1:
            sleep(30 * (attempt + 1))
            continue
        raise EnrolError(STATUS_CODES.get(status, "unexpected"), status)
    raise EnrolError("rate-limited", 429)


def confirmation_code(agent_id: str, rid: str) -> str:
    """M1: the first 8 hex of SHA-256 over "<agent_id>\\n<request_id>" (lowercase, UTF-8, one LF, no trailing
    newline). The bootstrap prints it; the App computes the same from the agent list and the request id the bus
    recorded; the operator compares them before the Windows Hello that adds this host to the fleet."""
    return hashlib.sha256(f"{agent_id.lower()}\n{rid.lower()}".encode("utf-8")).hexdigest()[:8]
