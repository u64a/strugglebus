"""A device reads each channel's purpose, how busy it is and who is listening."""

from __future__ import annotations

from types import SimpleNamespace

from strugglebus.routes import mobile as mobile_routes
from test_mobile_surface import _auth, mobile  # noqa: F401

ACTIVITY = "/api/mobile/channels/activity"


def test_every_channel_is_listed_with_its_purpose_counts_and_last_activity(mobile) -> None:  # noqa: F811
    client, secret, agents, board = mobile
    reader = agents.create_agent("reader-agent").agent
    board.create_channel("quiet", purpose="Nothing yet. No secrets.", created_by=reader.id)
    before = _listening(agents, "status")
    board.subscribe("status", agent_id=reader.id)

    answer = client.get(ACTIVITY, headers=_auth(secret))

    assert answer.status_code == 200
    channels = {channel["name"]: channel for channel in answer.json()}
    assert [channel["name"] for channel in answer.json()] == sorted(channels)
    status = channels["status"]
    assert (status["purpose"], status["message_count"]) == ("test", 1)
    assert status["subscriber_count"] == _listening(agents, "status") >= before
    assert status["last_activity_at"] is not None
    quiet = channels["quiet"]
    assert (quiet["purpose"], quiet["message_count"], quiet["last_activity_at"]) == (
        "Nothing yet. No secrets.", 0, None,
    )
    assert set(status) == {"name", "purpose", "created_at", "message_count", "subscriber_count", "last_activity_at"}


def _listening(agents, channel: str) -> int:
    with agents.store._read_transaction() as connection:
        return connection.execute(
            """
            SELECT COUNT(*) FROM subscriptions s JOIN agents a ON a.id = s.agent_id
            JOIN channels c ON c.id = s.channel_id
            WHERE c.name = ? AND a.revoked_at IS NULL AND a.blocked_at IS NULL
            """,
            (channel,),
        ).fetchone()[0]


def test_it_needs_a_device_and_stays_readable_while_frozen(mobile) -> None:  # noqa: F811
    client, secret, _, _ = mobile

    assert client.get(ACTIVITY).status_code == 401
    client.app.state.access_freeze_service.freeze("incident")
    assert client.get(ACTIVITY, headers=_auth(secret)).status_code == 200


def test_channels_are_read_page_by_page_and_never_without_end() -> None:
    def channel(number: int):
        return SimpleNamespace(name=f"c{number:04d}")

    class Board:
        def __init__(self, total: int, *, always_more: bool = False) -> None:
            self.total, self.always_more, self.asked = total, always_more, []

        def channel_activity(self, *, after, limit):
            self.asked.append(after)
            start = 0 if after is None else int(after[1:]) + 1
            rows = tuple(channel(number) for number in range(start, min(start + limit, self.total)))
            return SimpleNamespace(channels=rows, has_more=self.always_more or start + limit < self.total)

    several = Board(250)
    assert [c.name for c in mobile_routes._every_channel(several)] == [f"c{n:04d}" for n in range(250)]
    assert several.asked == [None, "c0099", "c0199"]

    endless = Board(10**6, always_more=True)
    assert len(mobile_routes._every_channel(endless)) == mobile_routes._CHANNEL_PAGE * mobile_routes._CHANNEL_PAGES

    # A page that says there is more but holds nothing ends the reading.
    empty = Board(0, always_more=True)
    assert mobile_routes._every_channel(empty) == []
    assert empty.asked == [None]
