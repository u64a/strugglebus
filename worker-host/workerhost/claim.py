"""Claim protocol (design section 4).

  claim -> settle window -> re-read every reply to the task -> lowest valid claim seq wins.

A claim counts only if it replies to the task seq, carries the same task_id and digest, and comes
from a pinned host identity (agent_id AND agent_name). Any failure to re-read fails closed: the host
does not start and posts `yield` when it can. A coordinator `cancel` naming the task seq, seen in the
re-read, stops the start.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .validate import REPLY_KIND, TASK_KIND, Pin, canonical, sender_is


class BusLike(Protocol):
    def post(self, channel: str, kind: str, text: str, reply_to: int | None = None) -> int: ...
    def read_all(self, channel: str, since: int) -> list[dict]: ...


def reply_text(kind: str, task_id: str | None, digest: str, host: str, **extra) -> str:
    body = {"v": 1, "type": kind, "host": host, "digest": digest}
    if task_id:
        body["task_id"] = task_id
    body.update(extra)
    return canonical(body)


def parse_reply(msg: dict) -> dict | None:
    body = msg.get("body")
    if not isinstance(body, str) or len(body) > 4096:
        return None
    try:
        obj = json.loads(body)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) and obj.get("v") == 1 and isinstance(obj.get("type"), str) else None


def from_pinned(msg: dict, hosts: list[Pin]) -> bool:
    return any(sender_is(msg, h) for h in hosts)


def valid_claims(messages: list[dict], task_seq: int, task_id: str, digest: str, hosts: list[Pin]) -> list[int]:
    seqs = []
    for m in messages:
        if m.get("reply_to") != task_seq or m.get("kind") != REPLY_KIND or not from_pinned(m, hosts):
            continue
        body = parse_reply(m)
        if body and body.get("type") == "claim" and body.get("task_id") == task_id and body.get("digest") == digest:
            seqs.append(m["seq"])
    return sorted(seqs)


def cancelled(messages: list[dict], task_seq: int, coordinator: Pin) -> bool:
    for m in messages:
        if not sender_is(m, coordinator) or m.get("kind") != TASK_KIND:
            continue
        body = parse_reply(m)
        if body and body.get("type") == "cancel" and body.get("task") == task_seq:
            return True
    return False


@dataclass
class ClaimSession:
    bus: BusLike
    channel: str
    host_name: str
    task_seq: int
    task_id: str
    digest: str
    hosts: list[Pin]
    coordinator: Pin
    settle_seconds: float
    clock: Callable[[], float] = time.monotonic
    claim_seq: int | None = None
    settle_until: float = 0.0
    outcome: str = ""
    notes: list[str] = field(default_factory=list)

    def post_claim(self) -> bool:
        try:
            self.claim_seq = self.bus.post(self.channel, REPLY_KIND,
                                           reply_text("claim", self.task_id, self.digest, self.host_name),
                                           reply_to=self.task_seq)
        except Exception:  # noqa: BLE001 - any bus failure means no claim was made
            self.outcome = "claim-failed"
            return False
        self.settle_until = self.clock() + self.settle_seconds
        return True

    def ready(self) -> bool:
        return self.claim_seq is not None and self.clock() >= self.settle_until

    def decide(self) -> str:
        """win | lose | cancelled | unreadable | lost-claim  (only `win` may start)."""
        try:
            messages = self.bus.read_all(self.channel, self.task_seq)
        except Exception:  # noqa: BLE001 - fail closed
            self.outcome = "unreadable"
            return self.outcome
        if cancelled(messages, self.task_seq, self.coordinator):
            self.outcome = "cancelled"
            return self.outcome
        claims = valid_claims(messages, self.task_seq, self.task_id, self.digest, self.hosts)
        if self.claim_seq not in claims:
            self.outcome = "lost-claim"  # our own claim is not visible: fail closed
        elif claims[0] == self.claim_seq:
            self.outcome = "win"
        else:
            self.outcome = "lose"
        return self.outcome

    def post(self, kind: str, **extra) -> int | None:
        try:
            return self.bus.post(self.channel, REPLY_KIND, reply_text(kind, self.task_id, self.digest, self.host_name,
                                                                      **extra), reply_to=self.task_seq)
        except Exception:  # noqa: BLE001
            return None

    def yield_(self, reason: str) -> int | None:
        return self.post("yield", reason=reason)
