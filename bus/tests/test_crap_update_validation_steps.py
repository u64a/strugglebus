"""Refusal paths of the updater's socket, runtime, metadata and wire-format checks."""

from __future__ import annotations

from dataclasses import replace
from email.message import Message
import json
import os
from pathlib import Path
import socket
import stat
from types import SimpleNamespace

import pytest

from strugglebus import update_client as client
from strugglebus import update_source as source
from strugglebus import update_transport as transport
from strugglebus import update_worker as worker_module
from strugglebus.update_types import (
    RESPONSE_BYTES, UPDATE_SOURCE_REPOSITORY, UpdateError, UpdateRequest, encode_json,
)
from test_update_types import candidate, observation, operation, status

COMMIT, TREE = "a" * 40, "b" * 40


def refused(code: str):
    return pytest.raises(UpdateError, match=f"^{code}$")


# --- update_client: socket provenance -------------------------------------------------


def directory(mode: int = 0o755, uid: int = 0) -> SimpleNamespace:
    return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid)


@pytest.fixture
def socket_tree(monkeypatch):
    path = Path.cwd() / "updater" / "synthetic.sock"
    monkeypatch.setattr(client.sys, "platform", "linux")
    infos = {parent: directory() for parent in path.parents}
    infos[path] = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_dev=8, st_ino=9)
    seen: list[Path] = []

    def lstat(self):
        seen.append(self)
        return infos[self]

    monkeypatch.setattr(Path, "lstat", lstat)
    return path, infos, seen


def test_socket_identity_is_returned_after_every_ancestor_is_checked_root_first(socket_tree):
    path, _, seen = socket_tree

    assert client._verify_socket_path(path) == (8, 9)

    assert seen == [*reversed(path.parents), path]


@pytest.mark.parametrize("unsafe", [
    directory(0o775), directory(0o757), directory(uid=1000),
    SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=0),
    SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0),
])
def test_unsafe_ancestor_is_refused_before_the_socket_is_examined(socket_tree, unsafe):
    path, infos, seen = socket_tree
    infos[path.parent] = unsafe

    with refused("forbidden"):
        client._verify_socket_path(path)
    assert path not in seen

    with refused("forbidden"):
        client._verify_socket_parent(path.parent)
    assert client._verify_socket_parent(path.parent.parent) is None


@pytest.mark.parametrize("mode,uid", [
    (stat.S_IFSOCK | 0o600, 0), (stat.S_IFSOCK | 0o664, 0), (stat.S_IFSOCK | 0o660, 1000),
    (stat.S_IFREG | 0o660, 0), (stat.S_IFSOCK | 0o4660, 0),
])
def test_socket_must_be_a_root_owned_group_only_socket(socket_tree, mode, uid):
    path, infos, _ = socket_tree
    infos[path] = SimpleNamespace(st_mode=mode, st_uid=uid, st_dev=8, st_ino=9)

    with refused("forbidden"):
        client._verify_socket_path(path)


def test_socket_check_is_unavailable_off_linux_or_for_relative_paths(socket_tree, monkeypatch):
    path, _, seen = socket_tree

    with refused("unavailable"):
        client._verify_socket_path(Path("relative.sock"))
    monkeypatch.setattr(client.sys, "platform", "win32")
    with refused("unavailable"):
        client._verify_socket_path(path)

    assert seen == []


# --- update_client: binding a response to its request ---------------------------------


def check_request() -> UpdateRequest:
    return UpdateRequest("check", "1" * 32, "operator", "1.0.0", "release-one")


def prepare_request() -> UpdateRequest:
    return UpdateRequest(
        "prepare", "1" * 32, "operator", "1.0.0", "release-one",
        observation().observation_id, candidate().digest,
    )


def prepare_status():
    return replace(status(), operation=operation("accepted", "prepare"))


def test_matching_responses_are_bound():
    assert client._bind_response(UpdateRequest("status"), replace(status(), operation=None)) is None
    assert client._bind_response(UpdateRequest("status", "1" * 32), status()) is None
    assert client._bind_response(check_request(), status()) is None
    assert client._bind_response(prepare_request(), prepare_status()) is None
    # A check still running has nothing to observe yet.
    running = replace(status(), operation=operation("accepted"), observation=None)
    assert client._bind_response(check_request(), running) is None


def test_status_lookup_distinguishes_evicted_history_from_a_missing_operation():
    request = UpdateRequest("status", "1" * 32)
    evicted = replace(status(), operation=None, history_available=False)

    assert client._bind_response(request, evicted) is None
    with refused("invalid_response"):
        client._bind_response(request, replace(status(), operation=None))
    with refused("invalid_response"):
        client._bind_response(check_request(), evicted)


@pytest.mark.parametrize("request_factory,response", [
    (check_request, replace(status(), operation=operation(identity="9" * 32))),
    (check_request, replace(status(), history_available=False)),
    (check_request, replace(status(), operation=operation(action="prepare"))),
    (check_request, replace(status(), operation=replace(operation(), actor_id="intruder"))),
    (check_request, replace(status(), observation=None)),
    (check_request, replace(status(), observation=replace(
        observation(), application_version="9.9.9"))),
    (check_request, replace(status(), observation=replace(
        observation(), application_release_id="release-two"))),
    (prepare_request, replace(prepare_status(), operation=operation("accepted", "check"))),
    (prepare_request, replace(prepare_status(), observation=None)),
    (prepare_request, replace(prepare_status(), observation=replace(
        observation(), observation_id="9" * 32))),
    (prepare_request, replace(prepare_status(), observation=replace(
        observation(), discovery=replace(observation().discovery, candidate=None,
                                         complete=False)))),
    (prepare_request, replace(prepare_status(), observation=replace(
        observation(), discovery=replace(
            observation().discovery, candidate=candidate("3.0.0"))))),
    (prepare_request, replace(prepare_status(), observation=replace(
        observation(), application_version="9.9.9"))),
])
def test_response_for_a_different_operation_or_observation_is_invalid(request_factory, response):
    with refused("invalid_response"):
        client._bind_response(request_factory(), response)


def test_mutation_binding_checks_the_operation_before_the_observation():
    wrong_actor = replace(operation(), actor_id="intruder")

    with refused("invalid_response"):
        client._bind_mutation(check_request(), replace(status(), observation=None), wrong_actor)
    assert client._bind_mutation(check_request(), status(), operation()) is None


# --- update_worker: runtime provenance ------------------------------------------------


CURRENT = Path("/opt/strugglebus-updater/current")
TARGET = CURRENT.parent / "releases" / "0.2.33"
RELATIVE = Path("venv/lib/site-packages/strugglebus/update_worker.py")


class Runtime:
    """A synthetic root-owned updater install reached through the ``current`` link."""

    def __init__(self, monkeypatch) -> None:
        self.alias, self.path = CURRENT / RELATIVE, TARGET / RELATIVE
        self.link_target = os.fspath(TARGET)
        self.resolved = {CURRENT: TARGET, TARGET: TARGET, self.alias: self.path}
        self.link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        self.file = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        self.ancestry: list[Path] = []
        self.installed: Path = self.alias
        runtime = self

        def resolve(item, *, strict=False):
            assert strict is True
            value = runtime.resolved.get(item, item)
            if isinstance(value, Exception):
                raise value
            return value

        def readlink(item):
            if isinstance(runtime.link_target, Exception):
                raise runtime.link_target
            return runtime.link_target

        monkeypatch.setattr(worker_module, "__file__", str(self.alias))
        monkeypatch.setattr(Path, "absolute", lambda item: item)
        monkeypatch.setattr(Path, "is_absolute", lambda item: os.fspath(item).startswith(("/", "\\")))
        monkeypatch.setattr(Path, "resolve", resolve)
        monkeypatch.setattr(worker_module.os, "readlink", readlink)
        monkeypatch.setattr(worker_module, "check_ancestry", self.ancestry.append)
        monkeypatch.setattr(
            Path, "lstat", lambda item: runtime.link if item == CURRENT else runtime.file,
        )
        monkeypatch.setattr(
            worker_module.metadata, "distribution",
            lambda name: SimpleNamespace(locate_file=lambda relative: runtime.installed),
        )


@pytest.fixture
def runtime(monkeypatch) -> Runtime:
    return Runtime(monkeypatch)


def test_runtime_under_the_current_link_resolves_into_its_release(runtime):
    assert worker_module._resolve_runtime(runtime.alias, CURRENT) == runtime.path
    assert runtime.ancestry == [CURRENT]

    assert worker_module._validate_runtime() is None
    assert runtime.ancestry == [CURRENT, CURRENT, runtime.path]


def test_current_must_be_a_root_owned_link(runtime):
    runtime.link.st_uid = 1000
    with refused("forbidden"):
        worker_module._resolve_runtime(runtime.alias, CURRENT)
    runtime.link.st_uid = 0
    runtime.link.st_mode = stat.S_IFDIR | 0o755
    with refused("forbidden"):
        worker_module._resolve_runtime(runtime.alias, CURRENT)


@pytest.mark.parametrize("link_target", [
    "releases/0.2.33",
    "/opt/strugglebus-updater/elsewhere/0.2.33",
    "/opt/strugglebus-updater/releases/nested/0.2.33",
    "/tmp/releases/0.2.33",
    OSError("not a link"),
])
def test_current_must_point_directly_at_an_absolute_release_directory(runtime, link_target):
    runtime.link_target = link_target

    with refused("forbidden"):
        worker_module._resolve_runtime(runtime.alias, CURRENT)
    with refused("forbidden"):
        worker_module._validate_runtime()


def test_release_directory_must_not_itself_be_redirected(runtime):
    runtime.resolved[TARGET] = TARGET.parent / "0.2.34"
    with refused("forbidden"):
        worker_module._resolve_runtime(runtime.alias, CURRENT)

    runtime.resolved[TARGET] = FileNotFoundError("release removed")
    with refused("forbidden"):
        worker_module._resolve_runtime(runtime.alias, CURRENT)


def test_module_must_resolve_to_the_same_place_inside_the_release(runtime):
    runtime.resolved[runtime.alias] = TARGET / "venv/lib/site-packages/other/update_worker.py"
    with refused("forbidden"):
        worker_module._resolve_runtime(runtime.alias, CURRENT)

    runtime.resolved[runtime.alias] = FileNotFoundError("module removed")
    with refused("forbidden"):
        worker_module._resolve_runtime(runtime.alias, CURRENT)


def test_runtime_outside_the_current_link_must_not_be_reached_through_a_link(runtime):
    direct = Path("/usr/lib/python3/site-packages/strugglebus/update_worker.py")

    assert worker_module._resolve_runtime(direct, CURRENT) == direct
    assert runtime.ancestry == []

    runtime.resolved[direct] = Path("/home/user/site-packages/strugglebus/update_worker.py")
    with refused("forbidden"):
        worker_module._resolve_runtime(direct, CURRENT)
    runtime.resolved[direct] = ValueError("embedded null")
    with refused("forbidden"):
        worker_module._resolve_runtime(direct, CURRENT)


@pytest.mark.parametrize("path", [
    Path("/opt/site-packages/other/update_worker.py"),
    Path("/opt/dist-packages/strugglebus/update_worker.py"),
    Path("/strugglebus/update_worker.py"),
])
def test_runtime_file_outside_an_installed_package_is_refused_unexamined(runtime, path):
    with refused("forbidden"):
        worker_module._validate_runtime_file(path)
    assert runtime.ancestry == []


@pytest.mark.parametrize("mode,uid", [
    (stat.S_IFREG | 0o664, 0), (stat.S_IFREG | 0o646, 0), (stat.S_IFREG | 0o644, 1000),
    (stat.S_IFLNK | 0o644, 0), (stat.S_IFDIR | 0o755, 0),
])
def test_runtime_file_must_be_a_root_owned_unshared_regular_file(runtime, mode, uid):
    runtime.file.st_mode, runtime.file.st_uid = mode, uid

    with refused("forbidden"):
        worker_module._validate_runtime_file(runtime.path)
    assert runtime.ancestry == [runtime.path]
    with refused("forbidden"):
        worker_module._validate_runtime()


def test_running_module_must_be_the_installed_distribution_file(runtime):
    runtime.installed = runtime.path.parent / "other.py"
    with refused("forbidden"):
        worker_module._validate_runtime()

    missing = runtime.path.parent / "missing.py"
    runtime.installed = missing
    runtime.resolved[missing] = FileNotFoundError("not installed")
    with refused("forbidden"):
        worker_module._validate_runtime()

    runtime.installed = runtime.path
    assert worker_module._validate_runtime() is None


# --- update_worker: the inherited listening socket ------------------------------------


class Listener:
    def __init__(self, path: Path) -> None:
        self.family, self.type = socket.AF_UNIX, socket.SOCK_STREAM
        self.accepting = 1
        self.path = path
        self.closed = False
        self.blocking: bool | None = None

    def getsockopt(self, level, option):
        assert (level, option) == (socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        return self.accepting

    def getsockname(self):
        return str(self.path)

    def setblocking(self, flag):
        self.blocking = flag

    def close(self):
        self.closed = True


@pytest.fixture
def listener(monkeypatch):
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_ACCEPTCONN", 30, raising=False)
    value = Listener(Path.cwd() / "synthetic.sock")
    value.info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
    value.ancestry = []
    monkeypatch.setattr(worker_module, "check_ancestry", value.ancestry.append)
    monkeypatch.setattr(Path, "lstat", lambda item: value.info)
    monkeypatch.setattr(worker_module.os, "getpid", lambda: 100)
    monkeypatch.setenv("LISTEN_PID", "100")
    monkeypatch.setenv("LISTEN_FDS", "1")
    opened = []

    def open_socket(*, fileno):
        opened.append(fileno)
        return value

    value.opened = opened
    monkeypatch.setattr(worker_module.socket, "socket", open_socket)
    return value


def test_inherited_listener_is_adopted_non_blocking_from_descriptor_three(listener):
    assert worker_module.inherited_socket() is listener

    assert listener.opened == [3]
    assert listener.blocking is False and not listener.closed
    assert listener.ancestry == [listener.path]


@pytest.mark.parametrize("name,value", [
    ("LISTEN_PID", "101"), ("LISTEN_PID", None), ("LISTEN_FDS", "2"), ("LISTEN_FDS", "0"),
    ("LISTEN_FDS", None),
])
def test_socket_not_passed_to_this_process_is_never_opened(listener, monkeypatch, name, value):
    if value is None:
        monkeypatch.delenv(name)
    else:
        monkeypatch.setenv(name, value)

    with refused("forbidden"):
        worker_module.inherited_socket()

    assert listener.opened == []


def weaken(listener: Listener, change: str) -> None:
    if change == "family":
        listener.family = socket.AF_INET
    elif change == "type":
        listener.type = socket.SOCK_DGRAM
    elif change == "not-listening":
        listener.accepting = 0
    elif change == "owner":
        listener.info.st_uid = 1000
    elif change == "world-accessible":
        listener.info.st_mode = stat.S_IFSOCK | 0o666
    elif change == "owner-only":
        listener.info.st_mode = stat.S_IFSOCK | 0o600
    else:
        listener.info.st_mode = stat.S_IFREG | 0o660


@pytest.mark.parametrize("change", [
    "family", "type", "not-listening", "owner", "world-accessible", "owner-only", "not-a-socket",
])
def test_unsafe_inherited_listener_is_closed_and_refused(listener, change):
    weaken(listener, change)

    with refused("forbidden"):
        worker_module.inherited_socket()

    assert listener.closed and listener.blocking is None
    with refused("forbidden"):
        worker_module._validate_listener(listener)


def test_listener_type_is_checked_before_its_path_is_trusted(listener):
    listener.family = socket.AF_INET
    listener.getsockname = lambda: pytest.fail("address of a non-UNIX socket was read")

    with refused("forbidden"):
        worker_module._validate_listener(listener)

    assert listener.ancestry == []


def test_listener_is_closed_when_its_ancestry_is_unsafe(listener, monkeypatch):
    def unsafe(path):
        raise UpdateError("storage_unsafe")

    monkeypatch.setattr(worker_module, "check_ancestry", unsafe)

    with refused("storage_unsafe"):
        worker_module.inherited_socket()

    assert listener.closed


# --- update_source: the source identity carried in the release body -------------------


def body(**changes: object) -> str:
    value: dict[str, object] = {
        "source_commit": COMMIT, "source_repository": UPDATE_SOURCE_REPOSITORY,
        "source_tree": TREE, "version": 1,
    }
    value.update(changes)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def test_canonical_release_body_yields_the_source_commit_and_tree():
    assert source._source_identity(body()) == (COMMIT, TREE)
    assert source._source_metadata(body()) == json.loads(body())


@pytest.mark.parametrize("value", [
    None, 7, body().encode(), ["{}"],
    "", "not json", "{", "[]", '"text"', "1",
    body() + "\n", " " + body(), body().replace(",", ", "),
    json.dumps(json.loads(body())),
    json.dumps(dict(reversed(json.loads(body()).items())), separators=(",", ":")),
    body()[:-1] + ',"version":1}',
    body(version=2), body(version=True), body(version=1.0), body(version="1"),
    body(source_repository="NZCypher819/strugglebus-releases"), body(source_repository=None),
    body(source_commit="A" * 40), body(source_commit="a" * 39), body(source_commit=None),
    body(source_tree="b" * 64), body(source_tree=7),
    body(extra=True),
    '{"source_commit":"' + COMMIT + '","source_tree":"' + TREE + '","version":1}',
    body(source_commit=float("nan")), '{"version":NaN}', '{"version":Infinity}',
    body(source_commit="\ud800"),
    pytest.param('{"padding":"' + "x" * 512 + '"}', id="oversized"),
    pytest.param("[" * 100_000, id="deep-nesting"),
])
def test_release_body_that_is_not_the_exact_canonical_identity_is_unsupported(value):
    with refused("unsupported_release"):
        source._source_identity(value)


def test_release_body_is_bounded_in_bytes_not_characters():
    at_limit = '{"k":"' + "x" * (512 - 8) + '"}'
    assert len(at_limit) == 512
    assert source._source_metadata(at_limit) == {"k": "x" * 504}

    multibyte = '{"k":"' + "é" * 300 + '"}'
    assert len(multibyte) < 512 < len(multibyte.encode())
    with refused("unsupported_release"):
        source._source_metadata(multibyte)


# --- update_transport: Content-Length -------------------------------------------------


def headers(*lengths: str) -> Message:
    message = Message()
    for length in lengths:
        message["Content-Length"] = length
    return message


def test_declared_size_within_the_limit_is_returned():
    assert transport._size(headers("0"), 5) == 0
    assert transport._size(headers("5"), 5) == 5
    assert transport._size(headers("0000000005"), 5) == 5
    assert transport._size(headers(), 5) is None
    assert transport._content_length(headers("5")) == "5"
    assert transport._size({"Content-Length": "3"}, 5) == 3


@pytest.mark.parametrize("lengths", [("5", "5"), ("1", "2"), ("5", "")])
def test_repeated_content_length_is_invalid_metadata(lengths):
    with refused("invalid_metadata"):
        transport._size(headers(*lengths), 5)
    with refused("invalid_metadata"):
        transport._content_length(headers(*lengths))


@pytest.mark.parametrize("value", ["", " 5", "5 ", "+5", "-1", "5.0", "0x5", "٥", "²", 5])
def test_content_length_must_be_plain_ascii_digits(value):
    with refused("invalid_metadata"):
        transport._size({"Content-Length": value}, 5)


@pytest.mark.parametrize("value", [
    "6", "9999999999", "00000000001", pytest.param("1" * 5000, id="overlong"),
])
def test_content_length_over_the_limit_or_overlong_fails_verification(value):
    with refused("verification_failed"):
        transport._size(headers(value), 5)


# --- update_types: values allowed on the wire -----------------------------------------


def test_json_values_are_encoded_canonically():
    value = {"b": [1, True, None, "", "text"], "a": {"nested": -3}}

    assert encode_json(value, 100) == b'{"a":{"nested":-3},"b":[1,true,null,"","text"]}'


@pytest.mark.parametrize("value", [
    1.5, float("nan"), b"bytes", (1, 2), {1, 2}, object(),
    [1.5], {"key": 1.5}, {"key": [b"bytes"]}, {"key": {"inner": (1,)}},
    "line\nbreak", "\x7f", {"key": "tab\there"}, ["\x00"], "\ud800",
    {"": 1}, {1: "integer key"}, {"k" * 129: 1}, {"bad\nkey": 1}, {None: 1},
])
def test_json_values_outside_the_wire_format_are_invalid(value):
    with refused("invalid_request"):
        encode_json(value, RESPONSE_BYTES)


def nested(depth: int) -> list:
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


def test_json_nesting_is_bounded_and_scalars_at_the_limit_are_checked():
    assert encode_json(nested(16), RESPONSE_BYTES) == b"[" * 17 + b"]" * 17
    with refused("invalid_request"):
        encode_json(nested(17), RESPONSE_BYTES)

    deepest_invalid = nested(15)
    innermost = deepest_invalid
    while innermost[0]:
        innermost = innermost[0]
    innermost[0].append(1.5)
    with refused("invalid_request"):
        encode_json(deepest_invalid, RESPONSE_BYTES)


def test_encoded_size_is_bounded_exactly():
    assert encode_json("abc", 5) == b'"abc"'
    with refused("invalid_request"):
        encode_json("abc", 4)
