"""The catch-up drain registry: admission, continuation checks, and release of reservations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from strugglebus.drain import (
    MAX_CONTINUATION_LENGTH, CatchUpPage, CatchUpSnapshot, DrainRegistry, _Entry,
)
from strugglebus.errors import (
    CatchUpCapacityError, CatchUpUnavailableError, DomainValidationError,
)

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


def snapshot(agent_id: str = "alice", *, limit: int = 10, include_stale: bool = False,
             upper_seq: int = 50) -> CatchUpSnapshot:
    return CatchUpSnapshot(
        agent_id=agent_id, subscriptions=(("general", 0),), mention_cursor=0,
        upper_seq=upper_seq, overlap_since=NOW, stale_before=NOW,
        include_stale=include_stale, limit=limit,
    )


def registry(clock: Clock | None = None, *, maximum: int = 4, per_agent: int = 2) -> DrainRegistry:
    return DrainRegistry(
        maximum=maximum, per_agent=per_agent, ttl_seconds=300,
        monotonic=clock or Clock(),
    )


def run(drains: DrainRegistry, operation, *, agent_id: str = "alice", limit: int = 10,
        include_stale: bool = False, continuation: str | None = None) -> CatchUpPage:
    return drains.run(
        agent_id=agent_id, limit=limit, include_stale=include_stale,
        continuation=continuation, now=NOW, operation=operation,
    )


def page_at(position: int, *, complete: bool = False, calls: list | None = None):
    """An operation that builds one page ending at ``position``."""
    def operation(existing, after_seq, build_page):
        if calls is not None:
            calls.append((existing, after_seq))
        return build_page(existing or snapshot(), (), position, complete)
    return operation


def start(drains: DrainRegistry, position: int = 7) -> str:
    page = run(drains, page_at(position))
    assert page.continuation is not None
    return page.continuation


def test_first_page_reserves_a_snapshot_and_the_token_resumes_it():
    drains = registry()
    calls: list = []

    first = run(drains, page_at(7, calls=calls))

    assert calls == [(None, 0)]
    assert first.mode == "drain" and first.complete is False
    assert first.snapshot_seq == 50
    assert first.expires_at == NOW + timedelta(seconds=300)
    assert len(drains._entries) == 1

    second = run(drains, page_at(20, complete=True, calls=calls), continuation=first.continuation)

    assert calls[1] == (snapshot(), 7)
    assert second.complete is True and second.continuation is None
    # A resumed drain stays replayable until it expires, and says when that is.
    assert second.expires_at == NOW + timedelta(seconds=300)
    assert len(drains._entries) == 1
    assert run(drains, page_at(20, complete=True), continuation=first.continuation).complete


def test_single_page_drain_holds_no_reservation_and_reports_no_expiry():
    drains = registry()

    page = run(drains, page_at(3, complete=True))

    assert page.complete is True and page.continuation is None
    assert page.expires_at is None
    assert drains._entries == {}


def test_failed_first_page_releases_its_reservation_even_on_cancellation():
    drains = registry(maximum=1, per_agent=1)

    def interrupted(existing, after_seq, build_page):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run(drains, interrupted)

    assert drains._entries == {}
    assert start(drains)


def test_failed_resume_keeps_the_snapshot_for_a_retry():
    drains = registry()
    token = start(drains)

    def failing(existing, after_seq, build_page):
        raise RuntimeError("database went away")

    with pytest.raises(RuntimeError):
        run(drains, failing, continuation=token)

    assert len(drains._entries) == 1
    assert run(drains, page_at(9), continuation=token).continuation is not None


def test_capacity_is_refused_globally_and_per_agent_without_evicting():
    drains = registry(maximum=2, per_agent=1)
    alice = start(drains)

    with pytest.raises(CatchUpCapacityError, match="capacity reached"):
        run(drains, page_at(1))
    start_bob = run(drains, page_at(1), agent_id="bob")
    with pytest.raises(CatchUpCapacityError):
        run(drains, page_at(1), agent_id="carol")

    assert start_bob.continuation is not None
    assert len(drains._entries) == 2
    assert run(drains, page_at(9), continuation=alice).mode == "drain"


def test_expired_snapshots_free_capacity_and_their_tokens_stop_working():
    clock = Clock()
    drains = registry(clock, maximum=1, per_agent=1)
    token = start(drains)

    clock.value += 299.9
    with pytest.raises(CatchUpCapacityError):
        run(drains, page_at(1))

    clock.value += 0.1
    with pytest.raises(CatchUpUnavailableError, match="start a new drain"):
        run(drains, page_at(9), continuation=token)
    assert drains._entries == {}
    assert start(drains)


def test_page_cannot_be_published_once_the_deadline_passes_mid_operation():
    clock = Clock()
    drains = registry(clock)

    def slow(existing, after_seq, build_page):
        clock.value += 300
        return build_page(snapshot(), (), 5, False)

    with pytest.raises(CatchUpUnavailableError):
        run(drains, slow)

    assert drains._entries == {}


@pytest.mark.parametrize("continuation", [
    "",
    "not-a-token",
    "2." + "a" * 32 + ".7." + "b" * 64,
    "1." + "A" * 32 + ".7." + "b" * 64,
    "1." + "a" * 32 + ".-7." + "b" * 64,
    "1." + "a" * 32 + "." + "9" * 20 + "." + "b" * 64,
    "1." + "a" * 32 + ".7." + "b" * 64 + "\n",
    "x" * (MAX_CONTINUATION_LENGTH + 1),
    7,
    b"1." + b"a" * 32 + b".7." + b"b" * 64,
])
def test_malformed_continuation_is_invalid_before_any_lookup(continuation):
    drains = registry()
    start(drains)
    calls: list = []

    with pytest.raises(DomainValidationError, match="invalid catch-up continuation"):
        run(drains, page_at(9, calls=calls), continuation=continuation)

    assert calls == []
    assert len(drains._entries) == 1


def test_well_formed_token_for_an_unknown_snapshot_is_unavailable():
    drains = registry()

    with pytest.raises(CatchUpUnavailableError):
        run(drains, page_at(9), continuation="1." + "a" * 32 + ".7." + "b" * 64)


def test_token_for_a_reservation_without_a_committed_snapshot_is_unavailable():
    drains = registry()
    identifier = "c" * 32
    drains._entries[identifier] = _Entry(
        agent_id="alice", deadline=1000.0, expires_at=NOW,
    )

    with pytest.raises(CatchUpUnavailableError):
        run(drains, page_at(9), continuation=f"1.{identifier}.7." + "b" * 64)


@pytest.mark.parametrize("scope", [
    {"agent_id": "mallory"},
    {"limit": 11},
    {"include_stale": True},
])
def test_token_is_bound_to_the_agent_and_request_shape(scope):
    drains = registry()
    token = start(drains)
    calls: list = []

    with pytest.raises(DomainValidationError, match="invalid catch-up continuation"):
        run(drains, page_at(9, calls=calls), continuation=token, **scope)

    assert calls == []


def test_tampered_position_or_signature_is_refused():
    drains = registry()
    token = start(drains, position=7)
    version, identifier, position, signature = token.split(".")
    flipped = ("0" if signature[0] != "0" else "1") + signature[1:]

    for forged in (
        f"{version}.{identifier}.8.{signature}",
        f"{version}.{identifier}.{position}.{flipped}",
    ):
        with pytest.raises(DomainValidationError, match="invalid catch-up continuation"):
            run(drains, page_at(9), continuation=forged)

    other = registry()
    with pytest.raises(CatchUpUnavailableError):
        run(other, page_at(9), continuation=token)


def test_position_beyond_the_snapshot_is_refused_even_when_signed():
    drains = registry()
    token = start(drains)
    identifier = token.split(".")[1]
    calls: list = []

    def signed(position: int) -> str:
        prefix = f"1.{identifier}.{position}"
        return prefix + "." + drains._signature(prefix, "alice", snapshot())

    with pytest.raises(DomainValidationError, match="invalid catch-up continuation"):
        run(drains, page_at(9, calls=calls), continuation=signed(51))
    assert calls == []

    run(drains, page_at(50, complete=True, calls=calls), continuation=signed(50))
    assert calls == [(snapshot(), 50)]
