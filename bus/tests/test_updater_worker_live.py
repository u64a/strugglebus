"""Linux acceptance: real worker, forked jobs, Unix IPC, disk journal and TLS bus.

Only fixture ancestry/socket ownership are adapted. All processes use the same
non-root UID; this is not systemd, distinct-UID, dedicated-mount or ACL adoption
qualification. The anonymous public release API is synthetic, not an external service.
"""

import asyncio
from dataclasses import asdict, replace
import hashlib
import json
import os
import shutil
import signal
import socket
import stat
import struct
import sys
import time

import httpx
import pytest

from operator_test_support import PASSWORD, csrf, verifier
from live_test_support import Forms, _consume, _identity, _prove, trusted_https_server
from strugglebus.app import create_app
from strugglebus import update_client, update_source, update_storage, update_transport
from strugglebus.update_client import UpdateClient
from strugglebus.update_state import Journal, UpdateState, journal_to_json
from strugglebus.update_storage import SecureCache
from strugglebus.update_types import UpdateError, UpdateLimits
from strugglebus.update_worker import ProcessJobRunner, UpdateWorker
from test_update_source import (
    Response, fixture_api as fixture_api, publication as publication,
    test_canonical_candidate_code_is_never_imported_or_executed as install_candidate_sentinel,
)
from test_updater_live import _produce

ROOT = "/operator/updates"
LIMITS = UpdateLimits(check_timeout=15, prepare_timeout=45)
# Jobs stay blocked until the test releases them, so ordering proves the web
# path never waits on a job. These bounds only catch stalls, and must tolerate
# a CI runner shared by parallel test workers.
RESPONSIVE_SECONDS = 8
STREAM_SECONDS = 30  # below prepare_timeout, which bounds the held job


@pytest.fixture(autouse=True)
def _required_live_platform():
    if sys.platform != "linux":
        pytest.skip("Run this acceptance gate on real Linux, not an emulated socket")
    assert os.geteuid() != 0, "This acceptance gate must never run as root"
    assert hasattr(socket, "AF_UNIX") and hasattr(socket, "SO_PEERCRED") and hasattr(os, "fork")
    assert shutil.which("openssl"), "Missing OpenSSL is a gate failure, not a skipped TLS test"


def _write_signal(path, value):
    raw = json.dumps(value, sort_keys=True).encode()
    assert len(raw) <= 4096
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        assert os.write(fd, raw) == len(raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_signal(path):
    raw = path.read_bytes()
    assert len(raw) <= 4096
    return json.loads(raw)


def _wait_for_release(control, name, deadline):
    expires = min(deadline, time.monotonic() + 30)
    while not (control / name).exists():
        if time.monotonic() >= expires:
            raise UpdateError("timeout")
        time.sleep(0.01)


async def _await_signal(control, name, timeout=15):
    async with asyncio.timeout(timeout):
        while not (control / name).exists():
            assert not (control / "service-error.json").exists(), _read_signal(
                control / "service-error.json",
            )
            await asyncio.sleep(0.01)
    return _read_signal(control / name)


def _fixture_ancestry(monkeypatch, root):
    def owned_fixture(path, *, owner=0):
        assert path.is_absolute() and path.is_relative_to(root)
        for parent in (path.parent, *path.parents):
            if not parent.is_relative_to(root):
                continue
            info = parent.lstat()
            assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            assert info.st_mode & 0o022 == 0
    monkeypatch.setattr(update_storage, "check_ancestry", owned_fixture)


def _fixture_socket_provenance(monkeypatch, path, service_pid):
    def protected_socket(observed):
        assert observed == path
        info = path.lstat()
        assert stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
        assert stat.S_IMODE(info.st_mode) == 0o660
        return info.st_dev, info.st_ino

    def owned_server(writer):
        connection = writer.get_extra_info("socket")
        pid, uid, _ = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
        )
        assert pid == service_pid and uid == os.geteuid()

    monkeypatch.setattr(update_client, "_verify_socket_path", protected_socket)
    monkeypatch.setattr(update_client, "_verify_server_peer", owned_server)


class GatedReleaseSource:
    """Pause the second synthetic transfer after a real first file was fsynced."""

    def __init__(self, api, reader, control, failed):
        self.api, self.reader, self.control, self.failed = api, reader, control, failed
        self.policy_id = reader.policy_id

    def check(self, running_version, *, deadline):
        result = self.reader.check(running_version, deadline=deadline)
        _write_signal(self.control / "check-started.json", {
            "pid": os.getpid(), "worker_pid": os.getppid(),
        })
        _wait_for_release(self.control, "check-release.json", deadline)
        return result

    def prepare(self, candidate, directory, *, deadline):
        if not (self.control / "armed.json").exists():
            return self.reader.prepare(candidate, directory, deadline=deadline)
        original = self.api.asset_response

        def asset_response(request, asset_id):
            response = original(request, asset_id)
            if len(self.api.downloads) == 2:
                self._hold_after_first_file(candidate, directory, deadline)
                if self.failed:
                    payload = response.getvalue()
                    disposition = response.headers["Content-Disposition"]
                    response.close()
                    response = Response(
                        payload[:-1] + bytes([payload[-1] ^ 1]), request.full_url,
                        media=candidate.assets[1].media_type, Content_Disposition=disposition,
                    )
            return response

        self.api.asset_response = asset_response
        try:
            self.reader.prepare(candidate, directory, deadline=deadline)
        finally:
            _write_signal(self.control / "finished.json", {
                "pid": os.getpid(), "finished_ns": time.monotonic_ns(),
                "downloads": self.api.downloads,
            })

    def _hold_after_first_file(self, candidate, directory, deadline):
        first = candidate.assets[0]
        assert {path.name for path in directory.iterdir()} == {first.name}
        assert hashlib.sha256((directory / first.name).read_bytes()).hexdigest() == first.sha256
        _write_signal(self.control / "started.json", {
            "pid": os.getpid(), "worker_pid": os.getppid(), "started_ns": time.monotonic_ns(),
            "first_asset": first.name, "first_sha256": first.sha256,
        })
        _wait_for_release(self.control, "release.json", deadline)


async def _serve_worker(cache_path, socket_path, control, api, reader, failed):
    cache = SecureCache(cache_path, LIMITS)
    cache.acquire()
    cache.initialize(journal_to_json(Journal(update_source.POLICY_ID)))
    state = UpdateState(cache, update_source.POLICY_ID, LIMITS)
    runner = ProcessJobRunner(lambda: GatedReleaseSource(api, reader, control, failed), LIMITS)
    worker = UpdateWorker(state, runner, os.geteuid())
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o660)
    listener.listen(4)
    listener.setblocking(False)
    try:
        await worker.serve(listener)
        _write_signal(control / "ready.json", {"pid": os.getpid(), "uid": os.geteuid()})
        async with asyncio.timeout(90):
            while not (control / "stop.json").exists():
                await asyncio.sleep(0.02)
    finally:
        await worker.close()
        listener.close()
        cache.close()
        socket_path.unlink(missing_ok=True)


def _start_worker(cache_path, socket_path, control, api, reader, failed):
    pid = os.fork()
    if pid:
        return pid
    os.umask(0o077)
    code = 0
    try:
        asyncio.run(_serve_worker(cache_path, socket_path, control, api, reader, failed))
    except BaseException as error:
        _write_signal(control / "service-error.json", {
            "type": type(error).__name__, "code": getattr(error, "code", None),
        })
        code = 1
    finally:
        os._exit(code)


async def _stop_worker(pid, control):
    for name in ("release.json", "check-release.json"):
        if not (control / name).exists():
            _write_signal(control / name, {"release": True})
    _write_signal(control / "stop.json", {"stop": True})
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        waited, result = os.waitpid(pid, os.WNOHANG)
        if waited:
            assert result == 0, _read_signal(control / "service-error.json")
            return
        await asyncio.sleep(0.02)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    pytest.fail("Owned worker did not stop within its bounded shutdown deadline")


async def _terminal(client, operation_id):
    async with asyncio.timeout(20):
        while True:
            result = await client.status(operation_id)
            assert result.history_available and result.operation.operation_id == operation_id
            if result.operation.phase not in {"accepted", "running"}:
                return result
            await asyncio.sleep(0.01)


async def _login(operator, origin):
    challenge = csrf(await operator.get("/login"))
    result = await operator.post(
        "/login", data={"csrf": challenge, "password": PASSWORD}, headers={"Origin": origin},
    )
    assert result.status_code == 303, result.text


async def _prepare_review(operator, origin, observation):
    page = await operator.get(ROOT + "/review/" + observation.observation_id)
    assert page.status_code == 200, page.text
    fields = Forms(page.text).fields(ROOT + "/prepare") | {"password": PASSWORD}
    started = time.monotonic()
    result = await operator.post(ROOT + "/prepare", data=fields, headers={"Origin": origin})
    elapsed = time.monotonic() - started
    assert result.status_code == 303, result.text
    assert elapsed < RESPONSIVE_SECONDS, f"Prepare acknowledgement took {elapsed:.3f}s"
    return result.headers["location"], elapsed


def _asset_hashes(directory):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}


async def _initial_observation(base_url, trust, ipc, cache_path, control, failed):
    async with httpx.AsyncClient(
        base_url=base_url, verify=trust, trust_env=False, follow_redirects=False, timeout=10,
    ) as operator:
        await _login(operator, base_url)
        page = await operator.get(ROOT)
        started = time.monotonic()
        result = await operator.post(
            ROOT + "/check", data=Forms(page.text).fields(ROOT + "/check"),
            headers={"Origin": base_url},
        )
        check_ack_seconds = time.monotonic() - started
        assert result.status_code == 303, result.text
        assert check_ack_seconds < RESPONSIVE_SECONDS, f"Check acknowledgement took {check_ack_seconds:.3f}s"
        operation_id = result.headers["location"].rsplit("/", 1)[1]
        active_job = await _await_signal(control, "check-started.json")
        assert active_job["worker_pid"] == _read_signal(control / "ready.json")["pid"]
        os.kill(active_job["pid"], 0)
        pending = await ipc.status(operation_id)
        assert pending.operation.phase == "running" and pending.state == "checking"
        _write_signal(control / "check-release.json", {"release": True})
        checked = await _terminal(ipc, operation_id)
        assert checked.operation.phase == "succeeded", checked.operation
        assert checked.observation.discovery.candidate is not None
        prior = None
        if failed:
            location, _ = await _prepare_review(operator, base_url, checked.observation)
            prepared = await _terminal(ipc, location.rsplit("/", 1)[1])
            assert prepared.operation.phase == "succeeded", prepared.operation
            slot = cache_path / ("operation-" + prepared.prepared.operation_id)
            prior = (prepared.prepared, _asset_hashes(slot))
        return checked.observation, prior, check_ack_seconds


def _verify_durable_result(cache_path, operation_id, result, prior, failed):
    cache = SecureCache(cache_path, LIMITS)
    try:
        durable = UpdateState(cache, update_source.POLICY_ID, LIMITS)
        assert durable.status(operation_id) == result
        assert durable.journal.cleanup is None and durable.journal.quarantine is None
        prepared = result.prepared
        assert prepared is not None
        slot = cache.slot_path(prepared.operation_id)
        cache.validate_slot(prepared.operation_id, prepared.candidate)
        update_source.verify_prepared(prepared.candidate, slot, LIMITS)
        assert {path.name for path in slot.iterdir()} == (
            {a.name for a in prepared.candidate.assets} | {"release-statement.txt"}
        )
        assert len(list(slot.iterdir())) == 6
        assert {p.name for p in cache_path.iterdir()} == {
            update_storage.JOURNAL, update_storage.LOCK, slot.name,
        }
        if failed:
            assert result.operation.phase == "failed" and result.operation.error == "verification_failed"
            assert prepared == prior[0] and _asset_hashes(slot) == prior[1]
            assert prepared.operation_id != operation_id
            assert not cache.slot_path(operation_id).exists()
        else:
            assert result.operation.phase == "succeeded" and result.operation.error is None
            assert prepared.operation_id == operation_id
    finally:
        cache.close()


async def _exercise_bus(application, base_url, trust, server, thread, ipc, control, cache_path, failed):
    identity = _identity(application)
    configuration = asdict(application.state.config)
    frozen = application.state.access_freeze_service.status()
    observation, prior, check_ack_seconds = await _initial_observation(
        base_url, trust, ipc, cache_path, control, failed,
    )
    _write_signal(control / "armed.json", {"armed": True})
    agent = application.state.agent_service.create_agent("real-worker-continuity")
    streams, probes, timeline, status_seconds = [], [], [], []
    operation_id = None
    posts = 0

    async def observe(request):
        nonlocal posts
        if request.url.path == "/api/stream":
            streams.append(request.method)
        if request.method == "POST" and request.url.path == "/api/channels/help/messages":
            posts += 1
            if posts in {1, 50, 100}:
                began = time.monotonic()
                current = await ipc.status(operation_id)
                elapsed = time.monotonic() - began
                assert elapsed < RESPONSIVE_SECONDS, f"Running-job status took {elapsed:.3f}s"
                assert current.operation.phase == "running" and current.state == "preparing"
                probes.append(posts)
                status_seconds.append(elapsed)

    async with (
        httpx.AsyncClient(
            base_url=base_url, verify=trust, trust_env=False, follow_redirects=False, timeout=10,
        ) as operator,
        httpx.AsyncClient(
            base_url=base_url, verify=trust, trust_env=False, timeout=10,
            headers={"Authorization": "Bearer " + agent.api_key}, event_hooks={"request": [observe]},
        ) as agent_client,
    ):
        await _login(operator, base_url)
        await _prove(agent_client)
        async with agent_client.stream("GET", "/api/stream", params={"channel": "help", "since": 0}) as stream:
            assert stream.status_code == 200
            receipt_path, prepare_ack_seconds = await _prepare_review(operator, base_url, observation)
            operation_id = receipt_path.rsplit("/", 1)[1]
            started = await _await_signal(control, "started.json")
            assert started["worker_pid"] == _read_signal(control / "ready.json")["pid"]
            assert started["pid"] not in {os.getpid(), started["worker_pid"]}
            os.kill(started["pid"], 0)
            first_file = cache_path / ("operation-" + operation_id) / started["first_asset"]
            assert hashlib.sha256(first_file.read_bytes()).hexdigest() == started["first_sha256"]
            assert not (control / "finished.json").exists()
            assert (await operator.get(receipt_path)).status_code == 200
            accepted, observed = await asyncio.wait_for(
                asyncio.gather(_produce(agent_client, timeline), _consume(stream.aiter_lines())),
                timeout=STREAM_SECONDS,
            )
            assert accepted == observed and len(accepted) == 100
            assert len({item["id"] for item in observed}) == 100
            assert [item["metadata"]["updater_probe"] for item in observed] == list(range(100))
            assert streams == ["GET"] and probes == [1, 50, 100] and not stream.is_closed
            _write_signal(control / "release.json", {"release": True})
            result = await _terminal(ipc, operation_id)
            finished = await _await_signal(control, "finished.json")
            _verify_durable_result(cache_path, operation_id, result, prior, failed)
            with pytest.raises(ProcessLookupError):
                os.kill(started["pid"], 0)
            assert all(started["started_ns"] / 1e9 <= begin <= end <= finished["finished_ns"] / 1e9
                       for begin, end in timeline)
            assert (await operator.get("/healthz")).status_code == 200 and not stream.is_closed
            assert (await operator.get(receipt_path)).status_code == 200
        stored = await agent_client.get("/api/channels/help/messages", params={"limit": 100})
        assert stored.status_code == 200 and stored.json() == accepted
    assert _identity(application) == identity
    assert asdict(application.state.config) == configuration
    assert application.state.access_freeze_service.status() == frozen
    assert server.started and thread.is_alive()
    return {
        "failed_preparation": failed, "uid": os.geteuid(), "worker_pid": started["worker_pid"],
        "job_pid": started["pid"], "posts": len(accepted), "events": len(observed),
        "stream_connections": len(streams), "status_probes_during_posts": probes,
        "check_ack_seconds": check_ack_seconds, "prepare_ack_seconds": prepare_ack_seconds,
        "status_seconds": status_seconds, "check_running_after_ack": True,
        "prepare_running_after_ack": True,
        "all_posts_inside_preparation": True, "application_identity": identity,
        "preparation_started_ns": started["started_ns"], "preparation_finished_ns": finished["finished_ns"],
        "first_post_ns": int(timeline[0][0] * 1e9), "last_post_ns": int(timeline[-1][1] * 1e9),
        "first_message_id": observed[0]["id"], "last_message_id": observed[-1]["id"],
        "configuration_unchanged": True, "freeze_unchanged": True,
        "prepared_operation_id": result.prepared.operation_id, "operation_id": operation_id,
        "outcome": result.operation.phase, "prepared_assets": [a.name for a in result.prepared.candidate.assets],
        "prior_good_retained": failed, "distinct_uid_or_systemd_proven": False,
        "dedicated_mount_or_acl_confinement_proven": False,
        "verified_tls": True, "job_reaped": True, "prepared_file_count": 5,
    }


@pytest.mark.parametrize("failed", [False, True], ids=["verified-success", "tampered-replacement"])
async def test_real_worker_bus_continuity(app_config, tmp_path, monkeypatch, fixture_api, failed):
    api, reader = fixture_api
    install_candidate_sentinel(fixture_api, tmp_path)
    monkeypatch.setattr(update_transport, "_CLOCK", time.monotonic)
    monkeypatch.setattr(update_transport, "_SLEEP", time.sleep)
    cache_path, control, bus = (tmp_path / name for name in ("cache", "signals", "bus"))
    for directory in (cache_path, control, bus):
        directory.mkdir(mode=0o700)
    socket_path = tmp_path / "w.sock"
    assert len(os.fsencode(socket_path)) <= 107, "Use a short, project-owned --basetemp"
    _fixture_ancestry(monkeypatch, tmp_path)
    service_pid = _start_worker(cache_path, socket_path, control, api, reader, failed)
    try:
        ready = await _await_signal(control, "ready.json")
        assert ready == {"pid": service_pid, "uid": os.geteuid()}
        _fixture_socket_provenance(monkeypatch, socket_path, service_pid)
        monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier())
        ipc = UpdateClient(socket_path)

        def application_factory(base_url):
            return create_app(config=replace(
                app_config, data_dir=bus, database_path=bus / "bus.db",
                runtime_dir=bus / "run", backup_dir=bus / "backups",
                public_base_url=base_url, sse_poll_interval_ms=10, sse_heartbeat_seconds=1,
                updater_socket_path=socket_path,
            ))

        with trusted_https_server(application_factory, tmp_path) as running:
            result = await _exercise_bus(*running, ipc, control, cache_path, failed)
            assert not (tmp_path / "candidate-executed").exists()
            _write_signal(tmp_path / "worker-live-result.json", result)
    finally:
        await _stop_worker(service_pid, control)
