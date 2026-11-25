"""Bus.post: the request body it sends (kind check, reply_to, metadata), and the answers it accepts."""
from __future__ import annotations

import pytest

from workerhost.busclient import Bus, BusError


def bus_answering(status, reply):
    b = Bus("https://bus.example.lan", "", "tok")
    b.sent = []

    def call(method, path, *, body=None, query=None, token=None):
        b.sent.append((method, path, body))
        return status, reply

    b.call = call
    return b


def test_a_post_sends_body_kind_and_a_request_id_and_returns_the_seq():
    b = bus_answering(201, {"seq": 42})
    assert b.post("worker-hosts", "status", "host=box1") == 42
    method, path, body = b.sent[0]
    assert (method, path) == ("POST", "/api/channels/worker-hosts/messages")
    assert body["body"] == "host=box1" and body["kind"] == "status" and len(body["request_id"]) == 36
    assert "reply_to" not in body and "metadata" not in body


def test_reply_to_and_metadata_go_in_only_when_given():
    b = bus_answering(201, {"seq": 7})
    b.post("worker-hosts", "status", "x", reply_to=5, metadata={"sb_host_status": {"v": 1}})
    body = b.sent[0][2]
    assert body["reply_to"] == 5 and body["metadata"] == {"sb_host_status": {"v": 1}}


def test_the_channel_name_is_quoted_in_the_path():
    b = bus_answering(201, {"seq": 1})
    b.post("a b/c", "status", "x")
    assert b.sent[0][1] == "/api/channels/a%20b%2Fc/messages"


def test_an_unknown_kind_is_refused_before_anything_is_sent():
    b = bus_answering(201, {"seq": 1})
    with pytest.raises(ValueError):
        b.post("worker-hosts", "shout", "x")
    assert b.sent == []


@pytest.mark.parametrize("status, reply", [(500, {"seq": 1}), (201, {"no": "seq"}), (201, "text"),
                                           (201, {"seq": "1"})])
def test_anything_but_a_created_message_with_a_seq_is_an_error(status, reply):
    with pytest.raises(BusError):
        bus_answering(status, reply).post("worker-hosts", "status", "x")
