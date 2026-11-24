from __future__ import annotations

from contextlib import contextmanager, nullcontext
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import sys
import time
from types import SimpleNamespace
from typing import Any, Iterator
import urllib.error

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import promotion_transport as transport
from promotion_common import PromotionError
from release_qualification import ArtifactIdentity, _list_artifacts, resolve_qualification


ROOT = transport.ROOT
OWNER = transport.OWNER
TOKEN = "fixture-sensitive-token"
SHA = "a" * 40
POSIX = pytest.mark.skipif(os.name != "posix", reason="real POSIX deadline/process test")


class Response:
    def __init__(
        self, value: Any = None, *, status: int = 200,
        url: str = "https://api.github.com/user", body: bytes | None = None,
        media_type: str = "application/json",
    ) -> None:
        self.status = status
        self.url = url
        self.body = io.BytesIO(json.dumps(value).encode() if body is None else body)
        self.headers = Message()
        if media_type:
            self.headers["Content-Type"] = media_type

    def read(self, size: int = -1) -> bytes:
        return self.body.read(size)

    def geturl(self) -> str:
        return self.url

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: Any) -> None:
        self.body.close()


class Opener:
    def __init__(self, *results: Any) -> None:
        self.results = list(results)
        self.requests: list[Any] = []

    def open(self, request: Any, *, timeout: int) -> Response:
        assert timeout <= 30
        self.requests.append(request)
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/user", status, TOKEN, Message(), io.BytesIO(TOKEN.encode())
    )


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> Any:
    if os.name != "posix":
        monkeypatch.setattr(transport, "deadline", lambda seconds: nullcontext())

    def make(
        *results: Any, request_limit: int = transport.MAX_REQUESTS,
    ) -> tuple[transport.PromotionAPI, Opener]:
        opener = Opener(*results)
        client = transport.PromotionAPI(
            TOKEN, executable=str(Path.cwd() / "trusted gh.exe"),
            json_opener=opener, sleep=lambda seconds: None, request_limit=request_limit,
        )
        return client, opener

    return make


def tag_payload() -> dict[str, Any]:
    return {
        "tag": "v0.2.6", "object": SHA, "type": "commit",
        "message": "Strugglebus promotion v1\n{}\n",
        "tagger": {
            "name": OWNER, "email": f"{OWNER}@users.noreply.github.com",
            "date": "2026-09-05T00:00:00Z",
        },
    }


def test_public_surface_has_no_release_mutations_or_generic_request(api: Any) -> None:
    client, _ = api()
    for name in ("create_draft", "upload_asset", "publish_release", "request",
                 "post", "patch", "delete", "update_ref", "delete_ref"):
        assert not hasattr(client, name)
    assert TOKEN not in repr(client)
    assert TOKEN not in repr(client._transport)


@pytest.mark.parametrize("owner", ["other", "nzcypher819", None, 123])
def test_owner_mismatch_is_authentication_failure(api: Any, owner: Any) -> None:
    client, _ = api(Response({"login": owner}))
    with pytest.raises(PromotionError) as caught:
        client.get("user")
    assert caught.value.code == 4
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.invalid/user", "https://[", "//api.github.com/user",
        "/user", "user?ref=main", "repos/Other/strugglebus",
        "repos/NZCypher819/other", ROOT + "evil", ROOT + "/../other",
        ROOT + "/%2e%2e/other", ROOT + "/releases#fragment",
        ROOT + "\\releases", ROOT + "/releases\n", ROOT + "/releases\x7f",
        ROOT + "/actions/runs?per_page=101", ROOT + "/actions/runs?page=0",
        ROOT + "/actions/runs?page=5", ROOT + "/actions/runs?page=1&page=2",
        ROOT + "/actions/runs?access_token=" + TOKEN,
    ],
)
def test_read_paths_never_escape_host_repository_or_limits(api: Any, path: str) -> None:
    client, opener = api()
    with pytest.raises(PromotionError):
        client.get(path)
    assert not opener.requests


def test_optional_404_does_not_hide_auth_or_network_errors(api: Any) -> None:
    client, opener = api(error(404))
    assert client.optional_get(ROOT + "/git/ref/tags/v0.2.6") is None
    assert len(opener.requests) == 1
    for status in (401, 403):
        client, opener = api(error(status))
        with pytest.raises(PromotionError) as caught:
            client.optional_get(ROOT)
        assert caught.value.code == 4
        assert caught.value.__cause__ is None
        assert TOKEN not in str(caught.value)
        assert len(opener.requests) == 1
    client, opener = api(*(urllib.error.URLError(TOKEN) for _ in range(3)))
    with pytest.raises(PromotionError) as caught:
        client.optional_get(ROOT)
    assert caught.value.code == 5
    assert TOKEN not in str(caught.value)
    assert caught.value.__cause__ is None
    assert len(opener.requests) == 3


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, float("inf"), 10001])
def test_request_budget_requires_a_finite_bounded_integer(api: Any, limit: Any) -> None:
    with pytest.raises(PromotionError, match="request limit") as caught:
        api(request_limit=limit)
    assert caught.value.code == 3


def test_request_budget_stops_fast_reads_and_optional_404s(api: Any) -> None:
    client, opener = api(Response({}), error(404), request_limit=2)
    assert client.get(ROOT) == {}
    assert client.optional_get(ROOT + "/git/ref/tags/v0.2.6") is None
    with pytest.raises(PromotionError, match="request budget exhausted") as caught:
        client.get(ROOT)
    assert caught.value.code == 5
    assert len(opener.requests) == 2
    assert TOKEN not in str(caught.value)
    assert client._budget.remaining == 0


def test_request_budget_counts_each_retry_attempt(api: Any) -> None:
    client, opener = api(
        urllib.error.URLError(TOKEN), urllib.error.URLError(TOKEN), request_limit=2
    )
    with pytest.raises(PromotionError, match="request budget exhausted"):
        client.get(ROOT)
    assert len(opener.requests) == 2


def test_request_budget_counts_internal_publisher_pagination(api: Any) -> None:
    records = [{"id": number, "tag_name": "other"} for number in range(1, 101)]
    client, opener = api(error(404), Response(records), request_limit=2)
    with pytest.raises(PromotionError, match="request budget exhausted"):
        client.find_release(transport.REPOSITORY_ID, "v0.2.6")
    assert len(opener.requests) == 2


def test_mutations_share_the_instance_request_budget(api: Any) -> None:
    client, opener = api(Response(status=204, body=b""), request_limit=1)
    client.dispatch("v0.2.6", SHA)
    with pytest.raises(PromotionError, match="request budget exhausted"):
        client.create_ref("v0.2.6", SHA)
    assert len(opener.requests) == 1


def test_release_downloads_share_http_request_budget(api: Any, tmp_path: Path) -> None:
    client, opener = api(Response({}), request_limit=1)
    client.get(ROOT)
    asset_opener = Opener()
    client._transport._asset_opener = asset_opener
    with pytest.raises(PromotionError, match="request budget exhausted"):
        client.download_asset(
            transport.REPOSITORY_ID, 1, tmp_path / "asset.zip",
            expected_name="asset.zip", expected_size=10,
            expected_media_type="application/zip", expected_sha256="a" * 64,
        )
    assert len(opener.requests) == 1
    assert not asset_opener.requests


@pytest.mark.parametrize("operation", ["dispatch", "create_tag", "create_ref"])
def test_lost_mutation_response_is_never_retried(api: Any, operation: str) -> None:
    client, opener = api(urllib.error.URLError(TOKEN))
    with pytest.raises(PromotionError) as caught:
        if operation == "dispatch":
            client.dispatch("v0.2.6", SHA)
        elif operation == "create_tag":
            client.create_tag(tag_payload())
        else:
            client.create_ref("v0.2.6", SHA)
    assert len(opener.requests) == 1
    assert opener.requests[0].method == "POST"
    assert caught.value.code == 5
    assert TOKEN not in str(caught.value)


def test_dispatch_has_only_owner_approved_fixed_workflow_inputs(api: Any) -> None:
    client, opener = api(Response(status=204, body=b"", media_type=""))
    assert client.dispatch("v0.2.6", SHA) is None
    request = opener.requests[0]
    assert request.full_url == (
        f"https://api.github.com/{ROOT}/actions/workflows/"
        "release-qualification.yml/dispatches"
    )
    assert json.loads(request.data) == {
        "ref": "main",
        "inputs": {
            "release_tag": "v0.2.6", "release_commit": SHA, "approved_by": OWNER,
            "approval": "publish-exact-qualified-bytes",
        },
    }


@pytest.mark.parametrize(
    "response",
    [
        Response(status=204, body=b"x"),
        Response(status=204, body=b"", url="https://evil.invalid/user"),
        Response(status=204, body=b"", url="http://api.github.com/user"),
        Response(status=200, body=b""),
    ],
)
def test_dispatch_rejects_nonempty_wrong_status_or_origin(api: Any, response: Any) -> None:
    client, opener = api(response)
    with pytest.raises(PromotionError):
        client.dispatch("v0.2.6", SHA)
    assert len(opener.requests) == 1


def test_tag_and_ref_are_create_only_exact_payloads(api: Any) -> None:
    client, opener = api(Response({"sha": SHA}, status=201), Response({}, status=201))
    assert client.create_tag(tag_payload()) == {"sha": SHA}
    assert client.create_ref("v0.2.6", SHA) == {}
    assert [request.full_url for request in opener.requests] == [
        f"https://api.github.com/{ROOT}/git/tags",
        f"https://api.github.com/{ROOT}/git/refs",
    ]
    assert json.loads(opener.requests[0].data) == tag_payload()
    assert json.loads(opener.requests[1].data) == {"ref": "refs/tags/v0.2.6", "sha": SHA}


@pytest.mark.parametrize(
    "change",
    [
        {"force": True}, {"tag": "refs/heads/main"}, {"object": SHA + "\n"},
        {"type": "tree"}, {"message": "x" * (16 * 1024 + 1)},
        {"message": "\x1bmalicious"},
        {"tagger": {"name": "other", "email": "other@example.invalid", "date": "now"}},
    ],
)
def test_tag_payload_validation_precedes_network(api: Any, change: dict[str, Any]) -> None:
    client, opener = api()
    with pytest.raises(PromotionError):
        client.create_tag(tag_payload() | change)
    assert not opener.requests


def test_mutation_internal_allowlist_and_payload_byte_limit(api: Any) -> None:
    client, opener = api()
    with pytest.raises(PromotionError, match="not permitted"):
        client._post(ROOT + "/releases", {}, 201)
    with pytest.raises(PromotionError, match="size limit"):
        client._post(ROOT + "/git/tags", {"message": "x" * transport.MAX_PAYLOAD_BYTES}, 201)
    assert not opener.requests


@pytest.mark.parametrize("field,endpoint", [
    ("workflow_runs", "workflows/ci.yml/runs"), ("jobs", "runs/1/jobs"),
    ("artifacts", "runs/1/artifacts"),
])
@pytest.mark.parametrize("total,records", [
    (None, []), (True, [{"id": 1}]), (-1, []), (101, [{"id": n} for n in range(1, 101)]),
    (2, [{"id": 1}]), (0, [{"id": 1}]), (2, [{"id": 1}, {"id": 1}]),
    (1, [{"id": True}]),
])
def test_listings_reject_invalid_counts_truncation_and_duplicates(
    api: Any, field: str, endpoint: str, total: Any, records: Any,
) -> None:
    client, _ = api(Response({"total_count": total, field: records}))
    with pytest.raises(PromotionError):
        client.get(f"{ROOT}/actions/{endpoint}?per_page=100")


def test_existing_resolver_cannot_hide_overflowing_run_results(api: Any) -> None:
    client, _ = api(Response({"total_count": 101, "workflow_runs": []}))
    with pytest.raises(PromotionError, match="complete bound"):
        resolve_qualification(client, repository=transport.REPOSITORY_ID,
                              tag="v0.2.6", commit=SHA)


def test_existing_artifact_pagination_allows_exactly_full_then_empty_page(api: Any) -> None:
    records = [{"id": n} for n in range(1, 101)]
    client, opener = api(
        Response({"total_count": 100, "artifacts": records}),
        Response({"total_count": 100, "artifacts": []}),
    )
    assert _list_artifacts(client, transport.REPOSITORY_ID, 1) == records
    assert len(opener.requests) == 2
    assert "page=2" in opener.requests[1].full_url


def test_short_complete_artifact_page_and_counted_run_page_work(api: Any) -> None:
    client, _ = api(Response({"total_count": 1, "artifacts": [{"id": 1}]}),
                    Response({"total_count": 0, "workflow_runs": []}))
    assert _list_artifacts(client, transport.REPOSITORY_ID, 1) == [{"id": 1}]
    assert client.get(ROOT + "/actions/runs?per_page=100")["workflow_runs"] == []


def test_artifact_sentinel_rejects_drifted_count(api: Any) -> None:
    client, _ = api(Response({"total_count": 99, "artifacts": []}))
    with pytest.raises(PromotionError, match="incomplete"):
        client.get(ROOT + "/actions/runs/1/artifacts?per_page=100&page=2")


@pytest.mark.parametrize("identity", [
    ArtifactIdentity(0, "qualified", 10, "a" * 64),
    ArtifactIdentity(True, "qualified", 10, "a" * 64),
    ArtifactIdentity(1, "qualified", 0, "a" * 64),
    ArtifactIdentity(1, "qualified", transport.MAX_ARTIFACT_BYTES + 1, "a" * 64),
    ArtifactIdentity(1, "../qualified", 10, "a" * 64),
    ArtifactIdentity(1, "qualified", 10, "bad"),
])
def test_artifact_identity_limits_precede_processes(
    api: Any, identity: ArtifactIdentity, monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client, _ = api()
    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("invalid artifact identity must not start a process")
    monkeypatch.setattr(transport, "_process", unexpected)
    with pytest.raises(PromotionError, match="identity"):
        client.download_artifact(identity, tmp_path / "artifact.zip")


def test_json_body_limit_and_error_redaction(api: Any) -> None:
    for response in (
        Response(body=b"x" * (transport.MAX_RESPONSE_BYTES + 1)),
        Response(body=(TOKEN + "{broken").encode()),
        Response({}, url="https://evil.invalid/" + TOKEN),
    ):
        client, _ = api(response)
        with pytest.raises(PromotionError) as caught:
            client.get(ROOT)
        assert TOKEN not in str(caught.value)
        assert caught.value.__cause__ is None


def test_release_reads_delegate_without_exposing_mutations(api: Any) -> None:
    client, _ = api()
    calls = []
    client._transport = SimpleNamespace(
        find_release=lambda *args: calls.append(("find", args)) or {"id": 1},
        list_assets=lambda *args: calls.append(("list", args)) or [],
    )
    assert client.find_release(transport.REPOSITORY_ID, "v0.2.6") == {"id": 1}
    assert client.list_assets(transport.REPOSITORY_ID, 1) == []
    assert [call[0] for call in calls] == ["find", "list"]


def test_release_reads_reject_other_repository(api: Any) -> None:
    client, opener = api()
    with pytest.raises(PromotionError):
        client.find_release("someone/else", "v0.2.6")
    with pytest.raises(PromotionError):
        client.list_assets("someone/else", 1)
    assert not opener.requests


def test_wsl_environment_pins_captured_identity_and_disables_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "GH_DEBUG", "DEBUG"):
        monkeypatch.setenv(key, "alternate-identity")
    monkeypatch.setenv("WSLENV", "GH_TOKEN/p:GH_DEBUG/u:ARBITRARY/p")
    environment = transport._environment(TOKEN)
    assert environment["GH_TOKEN"] == TOKEN
    assert environment["GH_HOST"] == "github.com"
    assert environment["GH_PROMPT_DISABLED"] == "1"
    for key in ("GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
                "GH_DEBUG", "DEBUG", "GH_HTTP_UNIX_SOCKET"):
        assert environment[key] == ""
        assert key in environment["WSLENV"].split(":")
    assert "GH_TOKEN" in environment["WSLENV"].split(":")
    assert "/" not in environment["WSLENV"]
    assert "ARBITRARY" not in environment["WSLENV"]


@pytest.mark.parametrize("selected", ["gh", "explicit"])
def test_factory_captures_credential_once_and_checks_owner(
    monkeypatch: pytest.MonkeyPatch, selected: str,
) -> None:
    executable = str(Path.cwd() / "trusted gh.exe")
    monkeypatch.setattr(transport, "_posix", lambda: None)
    monkeypatch.setattr(transport.shutil, "which", lambda name: executable)
    calls = []

    def capture(exe: str, args: list[str], **kwargs: Any) -> bytes:
        calls.append((exe, args, kwargs))
        return TOKEN.encode() + b"\r\n"

    monkeypatch.setattr(transport, "_process", capture)
    monkeypatch.setattr(transport.PromotionAPI, "get", lambda self, path: {"login": OWNER})
    client = transport.PromotionAPI.from_gh("gh" if selected == "gh" else executable)
    assert len(calls) == 1
    assert calls[0][0] == executable
    assert calls[0][1] == ["auth", "token", "--hostname", "github.com"]
    assert calls[0][2]["maximum"] == 4096
    assert calls[0][2]["seconds"] == 10
    assert client._token == TOKEN
    assert client._budget.remaining == transport.MAX_REQUESTS - 1
    assert TOKEN not in repr(client)
    monkeypatch.setattr(transport.PromotionAPI, "get", lambda self, path: {"login": "other"})
    with pytest.raises(PromotionError) as caught:
        transport.PromotionAPI.from_gh(executable)
    assert caught.value.code == 4


def test_factory_counts_both_auth_capture_and_initial_identity_request(
    api: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "_posix", lambda: None)
    monkeypatch.setattr(transport, "_process", lambda *args, **kwargs: TOKEN.encode())
    opener = Opener(Response({"login": OWNER}))
    original = transport._PromotionReleaseAPI
    monkeypatch.setattr(
        transport, "_PromotionReleaseAPI",
        lambda *args, **kwargs: original(*args, **kwargs, json_opener=opener),
    )
    client = transport.PromotionAPI.from_gh(str(Path.cwd() / "trusted gh.exe"))
    assert len(opener.requests) == 1
    assert client._budget.remaining == transport.MAX_REQUESTS - 2


@pytest.mark.parametrize("value", ["gh.exe", "./gh", "bin/gh", "bad\npath"])
def test_explicit_cli_selection_requires_trusted_absolute_path(value: str) -> None:
    with pytest.raises(PromotionError) as caught:
        transport._selected_executable(value)
    assert caught.value.code == 3


def test_native_windows_execution_refuses_without_spawning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport, "os", SimpleNamespace(name="nt"))
    with pytest.raises(PromotionError, match="Linux or WSL") as caught:
        transport.PromotionAPI.from_gh()
    assert caught.value.code == 3


@POSIX
def test_archive_subprocesses_share_http_request_budget(
    api: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, opener = api(Response({}), request_limit=2)
    client.get(ROOT)
    calls = []

    def identity(*args: Any, **kwargs: Any) -> bytes:
        calls.append(args)
        return json.dumps({"login": OWNER}).encode()

    monkeypatch.setattr(transport, "_process", identity)
    artifact = ArtifactIdentity(1, "qualified", 10, "a" * 64)
    destination = tmp_path / "archive.zip"
    with pytest.raises(PromotionError, match="request budget exhausted"):
        client.download_artifact(artifact, destination)
    assert len(opener.requests) == 1
    assert len(calls) == 1
    assert not destination.exists()
    assert client._budget.remaining == 0


@pytest.fixture
def executable(tmp_path: Path) -> Any:
    def write(source: str, *, name: str = "gh") -> str:
        path = tmp_path / name
        path.write_text("#!/usr/bin/python3\n" + source, encoding="utf-8")
        if not os.access(path, os.X_OK):
            path.chmod(0o700)
        return str(path)
    return write


@POSIX
@pytest.mark.parametrize("stream", [1, 2])
def test_real_process_enforces_stdout_and_stderr_limits(executable: Any, stream: int) -> None:
    selected = executable(f"import os\nos.write({stream}, b'x' * 100000)\n")
    with pytest.raises(PromotionError, match="output exceeded"):
        transport._process(selected, [], environment={}, maximum=4096, seconds=3)


@POSIX
def test_real_process_failure_never_surfaces_stderr(executable: Any) -> None:
    selected = executable(f"import sys\nsys.stderr.write({TOKEN!r})\nsys.exit(1)\n")
    with pytest.raises(PromotionError) as caught:
        transport._process(selected, [], environment={}, maximum=4096, seconds=3)
    assert TOKEN not in str(caught.value)
    assert caught.value.__cause__ is None


@contextmanager
def _ready_child(selected: str, children: list[Any]) -> Iterator[Any]:
    try:
        child = transport._StartedProcess(
            children, [selected], stdin=transport.subprocess.DEVNULL,
            stdout=transport.subprocess.PIPE, stderr=transport.subprocess.PIPE,
            env={}, shell=False,
        )
        assert child.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=1), "fixture readiness timed out"
            assert os.read(child.stdout.fileno(), 1) == b"R", "fixture readiness failed"
        yield child
    finally:
        # Independent fallback owns cleanup even when readiness or the test fails.
        for child in children:
            try:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=1)
            finally:
                for stream in (getattr(child, "stdout", None), getattr(child, "stderr", None)):
                    if stream is not None:
                        stream.close()


@POSIX
@pytest.mark.parametrize("startup_delay", [0, .2], ids=["immediate", "delayed-start"])
def test_process_timeout_kills_and_reaps_sigterm_resistant_child(
    executable: Any, monkeypatch: pytest.MonkeyPatch, startup_delay: float,
) -> None:
    selected = executable(
        f"import os,signal,time\ntime.sleep({startup_delay!r})\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\nos.write(1,b'R')\n"
        "while True: time.sleep(.01)\n"
    )
    children = []
    started = time.monotonic()
    with _ready_child(selected, children) as child:
        adopted = []

        def spawn(owned: list[Any], arguments: list[str], **kwargs: Any) -> Any:
            assert arguments == [selected]
            owned.append(child)
            adopted.append(child)
            return child

        # Start the short alarm only after the real child installed SIGTERM-ignore.
        monkeypatch.setattr(transport, "_StartedProcess", spawn)
        with pytest.raises(PromotionError) as caught:
            with transport.deadline(0.1):
                transport._process(selected, [], environment={}, maximum=4096, seconds=3)
        assert caught.value.code == 5
        assert time.monotonic() - started < 2
        assert adopted == children == [child]
        assert child.poll() == -signal.SIGKILL
        assert child.stdout.closed and child.stderr.closed
        with pytest.raises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)


@POSIX
@pytest.mark.parametrize("mode", ["timeout", "wrong-marker", "early-exit"])
def test_failed_child_readiness_kills_reaps_and_closes_pipes(
    executable: Any, mode: str,
) -> None:
    selected = executable(
        "import os,signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        + ("os.write(1,b'X')\n" if mode == "wrong-marker" else "")
        + ("while True: time.sleep(.01)\n" if mode != "early-exit" else "")
    )
    children = []
    started = time.monotonic()
    with pytest.raises(AssertionError, match="fixture readiness"):
        with _ready_child(selected, children):
            pytest.fail("unready child was admitted")
    assert time.monotonic() - started < 2
    assert len(children) == 1 and children[0].poll() is not None
    assert children[0].returncode == (0 if mode == "early-exit" else -signal.SIGKILL)
    assert children[0].stdout.closed and children[0].stderr.closed
    with pytest.raises(ChildProcessError):
        os.waitpid(children[0].pid, os.WNOHANG)


@POSIX
def test_keyboard_interrupt_cleans_up_exact_child(
    executable: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = executable("import time\ntime.sleep(10)\n")
    children = []
    original = transport._StartedProcess

    def spawn(*args: Any, **kwargs: Any) -> Any:
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(transport, "_StartedProcess", spawn)
    monkeypatch.setattr(
        transport, "os",
        SimpleNamespace(**(vars(os) | {
            "read": lambda *args: (_ for _ in ()).throw(KeyboardInterrupt())
        })),
    )
    selected = executable("import os,time\nos.write(1,b'x')\ntime.sleep(10)\n")
    with pytest.raises(KeyboardInterrupt):
        transport._process(selected, [], environment={}, maximum=4096, seconds=3)
    assert len(children) == 1 and children[0].poll() is not None


@POSIX
def test_interrupted_process_constructor_still_reaps_child(
    executable: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = executable("import time\ntime.sleep(10)\n")
    children = []
    original = transport._StartedProcess.__init__

    def interrupted(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        children.append(self)
        raise KeyboardInterrupt

    monkeypatch.setattr(transport._StartedProcess, "__init__", interrupted)
    with pytest.raises(KeyboardInterrupt):
        transport._process(selected, [], environment={}, maximum=4096, seconds=3)
    assert len(children) == 1 and children[0].poll() is not None
    assert children[0].stdout.closed and children[0].stderr.closed


@POSIX
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_missing_capture_pipe_fails_explicitly_and_reaps_child(
    executable: Any, monkeypatch: pytest.MonkeyPatch, stream: str,
) -> None:
    selected = executable("import time\ntime.sleep(10)\n")
    children = []
    original = transport._StartedProcess

    def missing_pipe(*args: Any, **kwargs: Any) -> Any:
        child = original(*args, **kwargs)
        getattr(child, stream).close()
        setattr(child, stream, None)
        children.append(child)
        return child

    monkeypatch.setattr(transport, "_StartedProcess", missing_pipe)
    with pytest.raises(PromotionError, match="capture pipes are unavailable") as caught:
        transport._process(selected, [], environment={}, maximum=4096, seconds=3)
    assert caught.value.code == 5
    assert len(children) == 1 and children[0].poll() is not None


@POSIX
def test_nested_deadline_retains_earlier_alarm_and_remaining_time() -> None:
    original_handler = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()
    with pytest.raises(PromotionError, match="wall-clock"):
        with transport.deadline(.15):
            with transport.deadline(.02):
                time.sleep(.005)
            with transport.deadline(5):
                time.sleep(2)
    assert .10 < time.monotonic() - started < .8
    assert signal.getsignal(signal.SIGALRM) == original_handler
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)


@POSIX
def test_nested_short_deadline_restores_outer_after_caught_timeout() -> None:
    started = time.monotonic()
    with pytest.raises(PromotionError):
        with transport.deadline(.15):
            with pytest.raises(PromotionError):
                with transport.deadline(.03):
                    time.sleep(1)
            time.sleep(1)
    assert .1 < time.monotonic() - started < .8


@POSIX
def test_slow_body_is_interrupted_by_total_request_budget(api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    class SlowResponse(Response):
        def read(self, size: int = -1) -> bytes:
            while True:
                time.sleep(.01)

    client, opener = api(SlowResponse({}))
    monkeypatch.setattr(transport, "REQUEST_SECONDS", .05)
    started = time.monotonic()
    with pytest.raises(PromotionError) as caught:
        client.get(ROOT)
    assert caught.value.code == 5
    assert len(opener.requests) == 1
    assert time.monotonic() - started < .8


@POSIX
@pytest.mark.parametrize("mode", ["valid", "size", "digest", "overflow", "wrong-owner"])
def test_real_gh_exe_archive_acquisition_is_bounded_and_bound_to_captured_token(
    executable: Any, tmp_path: Path, mode: str,
) -> None:
    content = b"fixture archive bytes"
    sent = content + b"overflow" if mode == "overflow" else content
    selected = executable(
        "import os,sys\n"
        f"assert os.environ['GH_TOKEN'] == {TOKEN!r}\n"
        "assert os.environ['GH_HOST'] == 'github.com'\n"
        "assert os.environ['GH_DEBUG'] == ''\n"
        "assert 'GH_TOKEN' in os.environ['WSLENV'].split(':')\n"
        "assert sys.argv[1:4] == ['api','--hostname','github.com']\n"
        "if sys.argv[4] == 'user':\n"
        f" print('{{\"login\":\"{'other' if mode == 'wrong-owner' else OWNER}\"}}')\n"
        "else:\n"
        f" assert sys.argv[4] == '{ROOT}/actions/artifacts/7/zip'\n"
        f" os.write(1, {sent!r})\n",
        name="selected gh.exe",
    )
    client = transport.PromotionAPI(TOKEN, executable=selected)
    artifact = ArtifactIdentity(
        7, "qualified", len(content) + (1 if mode == "size" else 0),
        "0" * 64 if mode == "digest" else hashlib.sha256(content).hexdigest(),
    )
    destination = tmp_path / "archive.zip"
    if mode == "valid":
        client.download_artifact(artifact, destination)
        assert destination.read_bytes() == content
    else:
        with pytest.raises(PromotionError):
            client.download_artifact(artifact, destination)
        assert not destination.exists()


@POSIX
def test_archive_deadline_removes_partial_and_reaps_process(
    executable: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = executable(
        "import os,sys,time\n"
        "if sys.argv[-1] == 'user':\n"
        f" print('{{\"login\":\"{OWNER}\"}}')\n"
        "else:\n os.write(1,b'partial')\n time.sleep(10)\n"
    )
    client = transport.PromotionAPI(TOKEN, executable=selected)
    monkeypatch.setattr(transport, "ARCHIVE_SECONDS", .1)
    artifact = ArtifactIdentity(1, "qualified", 100, "a" * 64)
    destination = tmp_path / "archive.zip"
    with pytest.raises(PromotionError) as caught:
        client.download_artifact(artifact, destination)
    assert caught.value.code == 5
    assert not destination.exists()


@POSIX
def test_exclusive_archive_destination_refuses_existing_file_and_symlink(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "archive.zip"
    destination.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        with transport._archive_destination(destination):
            pass
    assert destination.read_bytes() == b"preserve"
    link = tmp_path / "linked"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        with transport._archive_destination(link / "new.zip"):
            pass
    assert not (tmp_path / "new.zip").exists()


@POSIX
def test_release_asset_deadline_removes_partial_without_touching_existing_file(
    api: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = api()
    destination = tmp_path / "asset.zip"

    def slow(repository: str, asset_id: int, path: Path, **kwargs: Any) -> None:
        path.write_bytes(b"partial")
        time.sleep(10)

    monkeypatch.setattr(client._transport, "download_asset", slow)
    monkeypatch.setattr(transport, "REQUEST_SECONDS", .05)
    kwargs = dict(expected_name="asset.zip", expected_size=100,
                  expected_media_type="application/zip", expected_sha256="a" * 64)
    with pytest.raises(PromotionError) as caught:
        client.download_asset(transport.REPOSITORY_ID, 1, destination, **kwargs)
    assert caught.value.code == 5
    assert not destination.exists()
    destination.write_bytes(b"preserve")
    with pytest.raises(PromotionError, match="already exists"):
        client.download_asset(transport.REPOSITORY_ID, 1, destination, **kwargs)
    assert destination.read_bytes() == b"preserve"
