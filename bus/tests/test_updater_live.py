"""Verified-TLS bus continuity during synthetic worker admission/completion."""

import asyncio
from dataclasses import asdict, replace
from pathlib import Path
import threading
import time
from uuid import uuid4

import httpx
import pytest

from operator_test_support import PASSWORD, csrf, verifier
from live_test_support import Forms, _consume, _identity, _prove, trusted_https_server
from strugglebus.app import create_app
from strugglebus.update_types import UpdateOperation, UpdatePrepared
from test_operator_updates import ROOT, Worker


class DelayedWorker(Worker):
    def __init__(self, config, failed):
        super().__init__(config)
        self.failed = failed
        self.started = threading.Event()
        self.finish = threading.Event()
        self.finished = threading.Event()
        self.job = None
        self.interval = []

    async def prepare(self, operation_id, actor_id, version, release, observation_id, digest):
        self.calls.append(("prepare", operation_id, actor_id, version, release, observation_id, digest))
        assert observation_id == self.value.observation.observation_id
        assert digest == self.value.observation.discovery.candidate.digest
        self.value = replace(self.value, state="preparing", operation=UpdateOperation(
            operation_id, "prepare", actor_id, "running", int(time.time()), None, None,
        ))
        self.interval.append(time.monotonic())
        self.started.set()
        self.job = asyncio.create_task(self.complete())
        self.job.add_done_callback(lambda completed: self.finished.set())
        return self.value

    async def complete(self):
        released = await asyncio.to_thread(self.finish.wait, 30)
        try:
            assert released, "Continuity test did not release its synthetic cache job"
            operation = self.value.operation
            self.value = replace(
                self.value, state="failed" if self.failed else "prepared",
                operation=replace(
                    operation, phase="failed" if self.failed else "succeeded",
                    finished_at=int(time.time()), error="unavailable" if self.failed else None,
                ),
                prepared=None if self.failed else UpdatePrepared(
                    self.value.observation.discovery.candidate, int(time.time()), operation.operation_id,
                ),
            )
        finally:
            self.interval.append(time.monotonic())


async def _prepare(operator, origin):
    challenge = csrf(await operator.get("/login"))
    signed_in = await operator.post(
        "/login", data={"csrf": challenge, "password": PASSWORD}, headers={"Origin": origin},
    )
    assert signed_in.status_code == 303
    page = await operator.get(ROOT + "/review/" + "a" * 32)
    assert page.status_code == 200, page.text
    fields = Forms(page.text).fields(ROOT + "/prepare") | {"password": PASSWORD}
    result = await operator.post(ROOT + "/prepare", data=fields, headers={"Origin": origin})
    assert result.status_code == 303, result.text
    return result.headers["location"]


async def _produce(client, timeline):
    accepted = []
    for index in range(100):
        started = time.monotonic()
        response = await client.post("/api/channels/help/messages", json={
            "body": f"synthetic updater continuity message {index}",
            "metadata": {"updater_probe": index}, "request_id": str(uuid4()),
        })
        timeline.append((started, time.monotonic()))
        assert response.status_code == 201, response.text
        accepted.append(response.json())
    return accepted


@pytest.mark.parametrize("failed", [False, True])
async def test_preparation_preserves_100_posts_and_one_100_message_tls_stream(
    app_config, tmp_path, monkeypatch, failed,
):
    worker = DelayedWorker(app_config, failed)
    monkeypatch.setattr("strugglebus.operator_updates.UpdateClient", lambda path: worker)
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier())

    def application_factory(base_url):
        return create_app(config=replace(
            app_config, public_base_url=base_url, sse_poll_interval_ms=10, sse_heartbeat_seconds=1,
            updater_socket_path=Path(app_config.data_dir.anchor) / "updater-fixture" / "control.sock",
        ))

    with trusted_https_server(application_factory, tmp_path) as running:
        application, base_url, trust, server, thread = running
        identity = _identity(application)
        config = asdict(application.state.config)
        frozen = application.state.access_freeze_service.status()
        agent = application.state.agent_service.create_agent("updater-continuity")
        stream_requests = []

        async def observe(request):
            if request.url.path == "/api/stream":
                stream_requests.append(request.method)

        async with (
            httpx.AsyncClient(base_url=base_url, verify=trust, trust_env=False, follow_redirects=False, timeout=10) as operator,
            httpx.AsyncClient(
                base_url=base_url, verify=trust, trust_env=False, timeout=10,
                headers={"Authorization": "Bearer " + agent.api_key}, event_hooks={"request": [observe]},
            ) as client,
        ):
            await _prove(client)
            timeline = []
            try:
                async with client.stream("GET", "/api/stream", params={"channel": "help", "since": 0}) as stream:
                    assert stream.status_code == 200
                    receipt_path = await _prepare(operator, base_url)
                    assert worker.started.is_set()
                    assert not worker.finished.is_set()
                    assert (await operator.get("/healthz")).status_code == 200
                    status = await operator.get(receipt_path)
                    assert status.status_code == 200 and "preparing" in status.text
                    accepted, observed = await asyncio.wait_for(
                        asyncio.gather(_produce(client, timeline), _consume(stream.aiter_lines())), timeout=60,
                    )
                    assert accepted == observed
                    assert len(accepted) == 100 and len({message["id"] for message in accepted}) == 100
                    assert [message["metadata"]["updater_probe"] for message in observed] == list(range(100))
                    assert stream_requests == ["GET"] and not stream.is_closed
                    worker.finish.set()
                    assert await asyncio.to_thread(worker.finished.wait, 5)
                    result = await operator.get(receipt_path)
                    assert result.status_code == 200
                    assert ("Currently prepared files" in result.text) is not failed
                    assert (await operator.get("/healthz")).status_code == 200
                    assert not stream.is_closed
            finally:
                worker.finish.set()
                if worker.job is not None:
                    assert await asyncio.to_thread(worker.finished.wait, 5)
                    assert worker.job.done()
                    assert worker.job.exception() is None
            assert all(started >= worker.interval[0] and finished <= worker.interval[1] for started, finished in timeline)
            assert _identity(application) == identity
            assert asdict(application.state.config) == config
            assert application.state.access_freeze_service.status() == frozen
            assert server.started and thread.is_alive()
            stored = await client.get("/api/channels/help/messages", params={"limit": 100})
            assert stored.status_code == 200 and stored.json() == accepted
