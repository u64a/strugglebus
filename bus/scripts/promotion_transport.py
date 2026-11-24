"""Bounded owner transport with only the three approved promotion mutations."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
# Only the explicitly selected CLI runs, with shell-free arguments and bounded I/O.
import subprocess  # nosec B404
import threading
import time
from typing import Any, BinaryIO, Iterator
import urllib.parse

from promotion_common import PromotionError
from publish_immutable_release import (
    GitHubReleaseAPI,
    MAX_RESPONSE_BYTES,
    ReleasePublicationError,
    _exact_https_host,
)
from release_bundle import REPOSITORY_ID
from release_qualification import (
    APPROVAL_PHRASE,
    ArtifactIdentity,
    MAX_ARTIFACT_BYTES,
    QUALIFICATION_WORKFLOW,
)
from validate_release_trigger import GITHUB_API_URL


OWNER = "NZCypher819"
ROOT = f"repos/{REPOSITORY_ID}"
REQUEST_SECONDS = 30
TOKEN_SECONDS = 10
ARCHIVE_SECONDS = 300
MAX_TOKEN_BYTES = 4096
MAX_STDERR_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_LIST_RECORDS = 100
MAX_REQUESTS = 10000
_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _posix() -> None:
    if os.name != "posix" or not hasattr(signal, "setitimer"):
        raise PromotionError("promotion requires Linux or WSL", code=3)
    if threading.current_thread() is not threading.main_thread():
        raise PromotionError("promotion requires the main execution thread", code=3)


@contextmanager
def deadline(seconds: float) -> Iterator[None]:
    """Interrupt blocking work, retaining any earlier enclosing real-time alarm."""

    _posix()
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, (float, int))
        or not math.isfinite(seconds)
        or seconds <= 0
    ):
        raise PromotionError("deadline must be a positive finite duration", code=3)
    started = time.monotonic()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    earlier = previous_delay > 0 and previous_delay <= seconds
    fired = False

    def expired(signum: int, frame: Any) -> None:
        nonlocal fired
        fired = True
        if earlier and callable(previous_handler):
            previous_handler(signum, frame)
        raise PromotionError("promotion wall-clock deadline exceeded", code=5)

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(
        signal.ITIMER_REAL, min(seconds, previous_delay) if earlier else seconds
    )
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay:
            remaining = previous_delay - (time.monotonic() - started)
            if remaining <= 0 and fired and earlier:
                remaining = (
                    previous_interval - (-remaining % previous_interval)
                    if previous_interval else 0
                )
            elif remaining <= 0:
                remaining = 0.000001
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_interval)


class _RequestBudget:
    def __init__(self, limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= MAX_REQUESTS:
            raise PromotionError("promotion request limit is invalid", code=3)
        self.remaining = limit

    def consume(self) -> None:
        if self.remaining <= 0:
            raise PromotionError("promotion request budget exhausted", code=5)
        self.remaining -= 1


class _PromotionReleaseAPI(GitHubReleaseAPI):
    """Keep the publisher unchanged while supporting empty dispatch responses."""

    def __init__(self, *args: Any, budget: _RequestBudget, **kwargs: Any) -> None:
        self._budget = budget
        super().__init__(*args, **kwargs)

    def _headers(self, **kwargs: Any) -> dict[str, str]:
        # The publisher constructs fresh headers for each HTTP attempt, including
        # retries and its internal release-list pages.
        self._budget.consume()
        return super()._headers(**kwargs)

    def _decode_json_response(
        self, response: Any, *, expected_status: int, expected_host: str
    ) -> Any:
        if expected_status != 204:
            return super()._decode_json_response(
                response, expected_status=expected_status, expected_host=expected_host
            )
        if response.status != 204:
            raise ReleasePublicationError("GitHub dispatch response status is invalid")
        _exact_https_host(
            response.geturl(),
            allowed_hosts=frozenset({expected_host}),
            error_message="GitHub dispatch response origin changed",
        )
        if response.read(1):
            raise ReleasePublicationError("GitHub dispatch response was not empty")
        return None


@contextmanager
def _request_budget() -> Iterator[None]:
    try:
        with deadline(REQUEST_SECONDS):
            yield
    except ReleasePublicationError as error:
        message = str(error)
        if message in {
            "GitHub API authorization failed",
            "GitHub asset download authorization failed",
        }:
            safe = PromotionError("GitHub authorization failed", code=4)
        elif message in {
            "GitHub API network request failed",
            "GitHub API read retries were exhausted",
            "GitHub asset download network request failed",
            "GitHub asset download retries were exhausted",
        }:
            safe = PromotionError("GitHub network request failed", code=5)
        elif re.fullmatch(
            r"GitHub (?:API request|asset API request|asset delivery) failed with status "
            r"(?:429|500|502|503|504)",
            message,
        ):
            safe = PromotionError("GitHub service is unavailable", code=5)
        else:
            safe = PromotionError("GitHub returned an unsafe or conflicting response")
        raise safe from None
    except (OSError, ValueError, TypeError, RecursionError):
        raise PromotionError("GitHub transport failed", code=5) from None


def _selected_executable(executable: str) -> str:
    if (
        not isinstance(executable, str)
        or not executable
        or any(ord(character) < 32 or ord(character) == 127 for character in executable)
    ):
        raise PromotionError("selected GitHub CLI executable is invalid", code=3)
    if executable == "gh":
        selected = shutil.which("gh")
        if selected is None:
            raise PromotionError("selected GitHub CLI executable is unavailable", code=3)
        return os.path.abspath(selected)
    if not Path(executable).is_absolute():
        raise PromotionError("select GitHub CLI with an absolute trusted path", code=3)
    return executable


def _environment(token: str | None = None) -> dict[str, str]:
    environment = dict(os.environ)
    fixed = {
        "GH_HOST": "github.com",
        "GH_DEBUG": "",
        "DEBUG": "",
        "GH_HTTP_UNIX_SOCKET": "",
        "GH_PROMPT_DISABLED": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GH_ACCESSIBLE_PROMPTER": "0",
        "GH_FORCE_TTY": "",
        "GH_PAGER": "",
        "PAGER": "",
        "GH_BROWSER": "",
        "BROWSER": "",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "NO_COLOR": "1",
    }
    # Empty values clear inherited credentials, including on the Windows host.
    fixed.update(GH_ENTERPRISE_TOKEN="", GITHUB_ENTERPRISE_TOKEN="")  # nosec B106
    if token is not None:
        # Clear the fallback token; only the captured GH_TOKEN may authenticate.
        fixed.update(GH_TOKEN=token, GITHUB_TOKEN="")  # nosec B106
    environment.update(fixed)
    # Interop must replace the Windows host's token/debug settings too. Never
    # inherit WSLENV path-translation flags for the credential.
    forwarded = set(fixed) | {"GH_TOKEN", "GITHUB_TOKEN"}
    environment["WSLENV"] = ":".join(
        sorted(key for key in forwarded if key in environment)
    )
    return environment


class _StartedProcess(subprocess.Popen[bytes]):
    def __init__(
        self, started: list[subprocess.Popen[bytes]], *args: Any, **kwargs: Any
    ) -> None:
        # Popen can be interrupted after fork but before its constructor returns.
        started.append(self)
        super().__init__(*args, **kwargs)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Reap exactly the child we started, including after a deadline or Ctrl-C."""

    if not getattr(process, "_child_created", False):
        return
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        raise PromotionError("GitHub CLI cleanup failed", code=5) from None


def _process(
    executable: str,
    arguments: list[str],
    *,
    environment: dict[str, str],
    maximum: int,
    seconds: float,
    output: BinaryIO | None = None,
    failure_code: int = 5,
) -> bytes:
    captured = bytearray()
    started: list[subprocess.Popen[bytes]] = []
    try:
        with deadline(seconds):
            process = _StartedProcess(
                started,
                [executable, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
            )
            if process.stdout is None or process.stderr is None:
                raise PromotionError(
                    "GitHub CLI capture pipes are unavailable", code=failure_code
                )
            with selectors.DefaultSelector() as selector:
                counts = {"stdout": 0, "stderr": 0}
                for name, stream in (
                    ("stdout", process.stdout), ("stderr", process.stderr)
                ):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    for key, _ in selector.select(timeout=0.1):
                        name = key.data
                        bound = maximum if name == "stdout" else MAX_STDERR_BYTES
                        content = os.read(
                            key.fd, min(64 * 1024, bound - counts[name] + 1)
                        )
                        if not content:
                            selector.unregister(key.fileobj)
                            continue
                        counts[name] += len(content)
                        if counts[name] > bound:
                            raise PromotionError(
                                "GitHub CLI output exceeded its limit", code=failure_code
                            )
                        if name == "stdout":
                            if output is None:
                                captured.extend(content)
                            else:
                                output.write(content)
                if process.wait() != 0:
                    raise PromotionError("GitHub CLI request failed", code=failure_code)
        return bytes(captured)
    except OSError:
        raise PromotionError("GitHub CLI execution failed", code=failure_code) from None
    finally:
        if started:
            process = started[0]
            blocked = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGINT}
            )
            try:
                _stop_process(process)
            finally:
                for stream in (
                    getattr(process, "stdout", None), getattr(process, "stderr", None)
                ):
                    if stream is not None:
                        stream.close()
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)


def _require_owner(value: Any) -> None:
    if not isinstance(value, dict) or value.get("login") != OWNER:
        raise PromotionError("GitHub credential does not belong to the owner", code=4)


def _match(value: Any, pattern: re.Pattern[str], maximum: int) -> None:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or pattern.fullmatch(value) is None
    ):
        raise PromotionError("promotion mutation identity is invalid")


def _read_path(path: str) -> tuple[str, dict[str, str]]:
    if (
        not isinstance(path, str)
        or not path.isascii()
        or len(path) > 2048
        or any(ord(character) <= 32 or ord(character) == 127 for character in path)
        or "\\" in path
        or "#" in path
    ):
        raise PromotionError("GitHub read path is not permitted")
    try:
        parsed = urllib.parse.urlsplit(path)
    except ValueError:
        raise PromotionError("GitHub read path is not permitted") from None
    if (
        parsed.scheme
        or parsed.netloc
        or re.fullmatch(r"[A-Za-z0-9_./-]+", parsed.path) is None
        or any(part in {"", ".", ".."} for part in parsed.path.split("/"))
        or not (
            parsed.path == "user"
            or parsed.path == ROOT
            or parsed.path.startswith(ROOT + "/")
        )
    ):
        raise PromotionError("GitHub read path is not permitted")
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query, strict_parsing=True, max_num_fields=16
        )
    except ValueError:
        raise PromotionError("GitHub read query is invalid") from None
    query = dict(pairs)
    if len(query) != len(pairs) or (parsed.path == "user" and query):
        raise PromotionError("GitHub read query is invalid")
    for key, value in pairs:
        if (
            key not in {"page", "per_page", "head_sha", "event", "status", "ref",
                        "branch", "filter"}
            or len(value) > 256
            or not value.isascii()
            or any(ord(character) <= 32 or ord(character) == 127 for character in value)
        ):
            raise PromotionError("GitHub read query is invalid")
    for key, maximum in (("page", 4), ("per_page", MAX_LIST_RECORDS)):
        if key in query and (
            not query[key].isdecimal() or not 1 <= int(query[key]) <= maximum
        ):
            raise PromotionError("GitHub listing pagination is outside its bound")
    return parsed.path, query


def _complete_listing(path: str, query: dict[str, str], value: Any) -> None:
    if not path.startswith(ROOT + "/actions/"):
        return
    field = {"runs": "workflow_runs", "jobs": "jobs", "artifacts": "artifacts"}.get(
        path.rsplit("/", 1)[-1]
    )
    if field is None:
        return
    if not isinstance(value, dict):
        raise PromotionError("GitHub listing is invalid")
    total, records = value.get("total_count"), value.get(field)
    page, per_page = int(query.get("page", "1")), int(query.get("per_page", "30"))
    if (
        type(total) is not int
        or not 0 <= total <= MAX_LIST_RECORDS
        or not isinstance(records, list)
        or len(records) > per_page
    ):
        raise PromotionError("GitHub listing is invalid or exceeds its complete bound")
    if field == "artifacts" and page > 1:
        # The existing resolver asks for the empty next page after exactly 100.
        complete = (
            page == 2 and per_page == MAX_LIST_RECORDS
            and total == MAX_LIST_RECORDS and len(records) == 0
        )
    else:
        complete = page == 1 and total == len(records)
    if not complete:
        raise PromotionError("GitHub listing is truncated or incomplete")
    ids = [record.get("id") if isinstance(record, dict) else None for record in records]
    if (
        any(type(identity) is not int or not 1 <= identity <= 2**53 - 1 for identity in ids)
        or len(set(ids)) != len(ids)
    ):
        raise PromotionError("GitHub listing contains invalid or duplicate identities")


@contextmanager
def _archive_destination(destination: Path) -> Iterator[BinaryIO]:
    _posix()
    destination = destination.absolute()
    if destination.name in {"", ".", ".."} or ".." in destination.parts:
        raise PromotionError("artifact destination is unsafe")
    directory = os.open(destination.anchor, os.O_RDONLY | os.O_DIRECTORY)
    created = False
    try:
        for component in destination.parent.parts[1:]:
            next_directory = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        descriptor = os.open(
            destination.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        created = True
        with os.fdopen(descriptor, "wb") as output:
            metadata = os.fstat(output.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise PromotionError("artifact destination is unsafe")
            yield output
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if created:
            os.unlink(destination.name, dir_fd=directory)
        raise
    finally:
        os.close(directory)


class PromotionAPI:
    """Read-only release API plus dispatch, annotated tag, and create-only ref."""

    def __init__(
        self, token: str, *, executable: str = "gh",
        request_limit: int = MAX_REQUESTS, **transport: Any,
    ) -> None:
        self._budget = _RequestBudget(request_limit)
        self._executable = _selected_executable(executable)
        try:
            self._transport = _PromotionReleaseAPI(
                GITHUB_API_URL, token, budget=self._budget, **transport
            )
        except ReleasePublicationError:
            raise PromotionError("GitHub credential has an invalid format", code=4) from None
        self._token = token

    def __repr__(self) -> str:
        return f"{type(self).__name__}(repository={REPOSITORY_ID!r})"

    @classmethod
    def from_gh(cls, executable: str = "gh") -> PromotionAPI:
        _posix()
        selected = _selected_executable(executable)
        content = _process(
            selected, ["auth", "token", "--hostname", "github.com"],
            environment=_environment(), maximum=MAX_TOKEN_BYTES,
            seconds=TOKEN_SECONDS, failure_code=4,
        )
        try:
            token = content.decode("ascii").rstrip("\r\n")
        except UnicodeDecodeError:
            raise PromotionError("GitHub credential has an invalid format", code=4) from None
        api = cls(token, executable=selected)
        api._budget.consume()
        _require_owner(api.get("user"))
        return api

    def get(self, path: str) -> Any:
        endpoint, query = _read_path(path)
        with _request_budget():
            value = self._transport.get(path)
        _complete_listing(endpoint, query, value)
        if endpoint == "user":
            _require_owner(value)
        return value

    def optional_get(self, path: str) -> Any | None:
        endpoint, query = _read_path(path)
        with _request_budget():
            value = self._transport._request_json(path, allow_not_found=True)
        if value is not None:
            _complete_listing(endpoint, query, value)
            if endpoint == "user":
                _require_owner(value)
        return value

    def _post(self, path: str, payload: dict[str, Any], status: int) -> Any:
        allowed = {
            f"{ROOT}/actions/workflows/{QUALIFICATION_WORKFLOW}/dispatches": 204,
            f"{ROOT}/git/tags": 201,
            f"{ROOT}/git/refs": 201,
        }
        if allowed.get(path) != status:
            raise PromotionError("GitHub mutation is not permitted")
        try:
            content = json.dumps(
                payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")
            ).encode("ascii")
        except (TypeError, ValueError, RecursionError):
            raise PromotionError("GitHub mutation payload is invalid") from None
        if len(content) > MAX_PAYLOAD_BYTES:
            raise PromotionError("GitHub mutation payload exceeds its size limit")
        with _request_budget():
            return self._transport._request_json(
                path, method="POST", payload=payload, expected_status=status
            )

    def dispatch(self, tag: str, commit: str) -> None:
        _match(tag, _TAG, 64)
        _match(commit, _SHA, 40)
        self._post(
            f"{ROOT}/actions/workflows/{QUALIFICATION_WORKFLOW}/dispatches",
            {
                "ref": "main",
                "inputs": {
                    "release_tag": tag,
                    "release_commit": commit,
                    "approved_by": OWNER,
                    "approval": APPROVAL_PHRASE,
                },
            },
            204,
        )

    def create_tag(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {
            "tag", "object", "type", "message", "tagger"
        }:
            raise PromotionError("annotated tag payload is invalid")
        _match(payload["tag"], _TAG, 64)
        _match(payload["object"], _SHA, 40)
        tagger, message = payload["tagger"], payload["message"]
        if (
            payload["type"] != "commit"
            or not isinstance(message, str)
            or not 1 <= len(message) <= 16 * 1024
            or not message.isascii()
            or any(ord(char) < 32 and char != "\n" or ord(char) == 127 for char in message)
            or not isinstance(tagger, dict)
            or set(tagger) != {"name", "email", "date"}
            or tagger["name"] != OWNER
            or tagger["email"] != f"{OWNER}@users.noreply.github.com"
            or not isinstance(tagger["date"], str)
            or re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", tagger["date"]) is None
        ):
            raise PromotionError("annotated tag payload is invalid")
        try:
            datetime.strptime(tagger["date"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise PromotionError("annotated tag date is invalid") from None
        value = self._post(f"{ROOT}/git/tags", payload, 201)
        if not isinstance(value, dict):
            raise PromotionError("GitHub tag response is invalid")
        return value

    def create_ref(self, tag: str, tag_sha: str) -> dict[str, Any]:
        _match(tag, _TAG, 64)
        _match(tag_sha, _SHA, 40)
        value = self._post(
            f"{ROOT}/git/refs", {"ref": f"refs/tags/{tag}", "sha": tag_sha}, 201
        )
        if not isinstance(value, dict):
            raise PromotionError("GitHub ref response is invalid")
        return value

    def download_artifact(self, artifact: ArtifactIdentity, destination: Path) -> None:
        with deadline(ARCHIVE_SECONDS):
            self._download_artifact(artifact, destination)

    def _download_artifact(self, artifact: ArtifactIdentity, destination: Path) -> None:
        if (
            not isinstance(artifact, ArtifactIdentity)
            or type(artifact.id) is not int
            or not 1 <= artifact.id <= 2**53 - 1
            or not isinstance(artifact.name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact.name) is None
            or type(artifact.size_bytes) is not int
            or not 1 <= artifact.size_bytes <= MAX_ARTIFACT_BYTES
            or not isinstance(artifact.digest, str)
            or _DIGEST.fullmatch(artifact.digest) is None
        ):
            raise PromotionError("qualification artifact identity is invalid")
        environment = _environment(self._token)
        try:
            self._budget.consume()
            identity = _process(
                self._executable, ["api", "--hostname", "github.com", "user"],
                environment=environment, maximum=MAX_RESPONSE_BYTES,
                seconds=REQUEST_SECONDS,
            )
            try:
                _require_owner(json.loads(identity))
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise PromotionError("GitHub CLI identity response is invalid", code=4) from None
            with _archive_destination(destination) as output:
                digest = hashlib.sha256()

                class CheckedOutput:
                    size = 0

                    def write(self, content: bytes) -> None:
                        self.size += len(content)
                        digest.update(content)
                        output.write(content)

                checked = CheckedOutput()
                self._budget.consume()
                _process(
                    self._executable,
                    ["api", "--hostname", "github.com",
                     f"{ROOT}/actions/artifacts/{artifact.id}/zip"],
                    environment=environment, maximum=artifact.size_bytes,
                    seconds=ARCHIVE_SECONDS, output=checked,
                )
                if (
                    checked.size != artifact.size_bytes
                    or not hmac.compare_digest(digest.hexdigest(), artifact.digest)
                ):
                    raise PromotionError("qualification archive size or digest mismatch")
        except OSError:
            raise PromotionError("qualification archive acquisition failed", code=5) from None

    def find_release(self, repository: str, tag: str) -> dict[str, Any] | None:
        _match(tag, _TAG, 64)
        with _request_budget():
            return self._transport.find_release(repository, tag)

    def list_assets(self, repository: str, release_id: int) -> list[dict[str, Any]]:
        with _request_budget():
            return self._transport.list_assets(repository, release_id)

    def download_asset(
        self, repository: str, asset_id: int, destination: Path, *,
        expected_name: str, expected_size: int, expected_media_type: str,
        expected_sha256: str,
    ) -> None:
        if destination.exists() or destination.is_symlink():
            raise PromotionError("release asset destination already exists")
        try:
            with _request_budget():
                self._transport.download_asset(
                    repository, asset_id, destination, expected_name=expected_name,
                    expected_size=expected_size, expected_media_type=expected_media_type,
                    expected_sha256=expected_sha256,
                )
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
