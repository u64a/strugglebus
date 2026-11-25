from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from workerhost.validate import Context, Pin  # noqa: E402

COORD = Pin("11111111-1111-4111-8111-111111111111", "coord-main")
HOST_A = Pin("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sb-host-alpha")
HOST_B = Pin("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "sb-host-bravo")
STRANGER = Pin("99999999-9999-4999-8999-999999999999", "coord-host1")
COMMIT = "3f2a9c0d6b1e4f7a8c9d0e1f2a3b4c5d6e7f8a9b"
BRIEF = "tooling/briefs/_task-core14-export.txt"
BRIEF_TEXT = "Build the findings export.\n"
NOW = datetime(2026, 10, 9, 0, 0, tzinfo=timezone.utc)


def pytest_configure(config):
    config.addinivalue_line("markers", "fleet: uses real (local) fleet.toml fetches and its own signing keys")
    config.addinivalue_line("markers", "update: sets its own clock for the self-update window")
    config.addinivalue_line("markers", "winupdate: runs workerhost.winupdate itself (a fake or the real query)")


@pytest.fixture(autouse=True)
def no_real_windows_update_query(request, monkeypatch):
    """Host.maintain() asks Windows Update whether a restart is coming (a few seconds of PowerShell): never in tests,
    except those marked `winupdate`, which bring their own runner."""
    if "winupdate" not in request.keywords:
        from workerhost import winupdate

        monkeypatch.setattr(winupdate, "restart_expected", lambda *a, **k: False)


@pytest.fixture(autouse=True)
def copilot_counts_as_installed(monkeypatch):
    """Host tests assume the GHCP engine is usable, as every host did before engines existed. Without this, a machine
    without Copilot CLI (the CI runners) refuses every task with reason `engine`. Engine detection itself is tested
    directly in test_engines.py through engines.available()."""
    from workerhost.host import Host

    monkeypatch.setattr(Host, "available_engines", lambda self: ["ghcp"])


@pytest.fixture(autouse=True)
def no_real_fleet_fetch(request, monkeypatch, tmp_path):
    """No test reaches GitHub for fleet.toml, and none reads a real pinned signer list: a Host built without
    `signers=` gets an empty temp path, and refresh() reports fetch-failed. Tests marked `fleet` use local
    repositories and their own keys."""
    from workerhost import fleet, signing

    monkeypatch.setattr(signing, "pinned_path", lambda: tmp_path / "no-pinned-signers")
    if "fleet" not in request.keywords:
        monkeypatch.setattr(fleet.FleetSync, "refresh", lambda self, current: fleet.Outcome("fetch-failed"))
    if "update" not in request.keywords:
        # Self-update acts between 01:00 and 04:30 local time: other tests always run at midday, so a test run at
        # night never checks for, announces or applies a release. Tests marked `update` set their own clock.
        from datetime import datetime

        from workerhost import update

        monkeypatch.setattr(update, "now_local", lambda: datetime(2026, 11, 4, 12, 0))


class FakeVault:
    """A vault whose main holds COMMIT with one brief, and a side commit that is not on main."""

    def __init__(self, files: dict[str, bytes] | None = None, fetch_ok: bool = True):
        self.files = files if files is not None else {BRIEF: BRIEF_TEXT.encode()}
        self.fetch_ok = fetch_ok
        self.side = "0" * 40
        self.blobs = {}
        self.calls = []
        self.last_fetch_ok = None

    def fetch(self):
        self.calls.append("fetch")
        return self.fetch_ok

    def resolve_commit(self, commit):
        return commit if commit in (COMMIT, self.side) else None

    def on_main(self, commit):
        return commit == COMMIT

    def brief_entry(self, commit, path):
        data = self.files.get(path)
        if data is None:
            return None
        if isinstance(data, tuple):  # (mode, kind, bytes)
            mode, kind, data = data
        else:
            mode, kind = "100644", "blob"
        sha = hashlib.sha1(path.encode()).hexdigest()
        self.blobs[sha] = data
        return mode, kind, sha, len(data)

    def read_blob(self, sha):
        return self.blobs.get(sha, b"")


def task_body(**over) -> dict:
    body = {"v": 1, "type": "task", "task_id": "6f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f", "host": "any",
            "worker": "core14", "repo": "app-core", "branch": "feature/core14-findings-export",
            "brief": BRIEF, "vault_commit": COMMIT, "model": "claude-opus-5.5"}
    body.update(over)
    return {k: v for k, v in body.items() if v is not ...}


def message(body, sender: Pin = COORD, seq: int = 100, kind: str = "question", created: datetime | None = None,
            reply_to=None) -> dict:
    return {"seq": seq, "id": f"id-{seq}", "channel": "worker-hosts", "agent_id": sender.agent_id,
            "agent_name": sender.agent_name, "kind": kind, "reply_to": reply_to, "metadata": {},
            "body": body if isinstance(body, str) else json.dumps(body),
            "created_at": (created or NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")}


@pytest.fixture
def ctx() -> Context:
    return Context(host_name="alpha", coordinators=[COORD], repos={"app-core": "acme/app-core"},
                   allowed_models=["claude-opus-5.5", "gpt-5.5"], tags=["sshdrop"], vault=FakeVault(),
                   now=lambda: NOW)


class SharedBus:
    """An in-memory channel. Each host gets a client bound to its own identity (as the bus authenticates)."""

    def __init__(self):
        self.messages: list[dict] = []
        self.seq = 1000
        self.fail_reads_for: set[str] = set()

    def append(self, sender: Pin, kind: str, text: str, reply_to=None) -> int:
        self.seq += 1
        self.messages.append({"seq": self.seq, "agent_id": sender.agent_id, "agent_name": sender.agent_name,
                              "kind": kind, "body": text, "reply_to": reply_to,
                              "created_at": NOW.isoformat().replace("+00:00", "Z")})
        return self.seq

    def client(self, me: Pin) -> "BusClient":
        return BusClient(self, me)


class BusClient:
    def __init__(self, shared: SharedBus, me: Pin):
        self.shared, self.me = shared, me
        self.posts: list[dict] = []
        self.channel_posts: list[tuple[str, str, str]] = []  # (channel, kind, text): every post, any channel
        self.fail_channels: set[str] = set()
        # No call() here on purpose: code that subscribes with bus.call (leaf, announce) is skipped in the tests that
        # use this fake as it always was. A test that needs subscriptions adds a call (see test_models.host).

    def post(self, channel, kind, text, reply_to=None, metadata=None):
        if channel in self.fail_channels:
            raise OSError("channel refused")
        self.channel_posts.append((channel, kind, text))
        if metadata is not None:
            self.metadata_posts = getattr(self, "metadata_posts", []) + [metadata]
        seq = self.shared.append(self.me, kind, text, reply_to)
        self.posts.append({"seq": seq, "kind": kind, "body": json.loads(text) if text.startswith("{") else text,
                           "reply_to": reply_to})
        return seq

    def read_all(self, channel, since):
        if self.me.agent_name in self.shared.fail_reads_for:
            raise OSError("bus unreachable")
        return [dict(m) for m in self.shared.messages if m["seq"] > since]

    def read(self, channel, since=0, limit=100):
        return self.read_all(channel, since)[:limit]

    def newest_seq(self, channel):
        return self.shared.seq


@pytest.fixture
def shared_bus() -> SharedBus:
    return SharedBus()


def git(cwd: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture
def remote_and_clone(tmp_path: Path):
    """A bare 'origin' and a clone of it with one pushed commit on branch work."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-q", "-b", "main", str(origin)], check=True)
    clone = tmp_path / "workers" / "core14"
    clone.parent.mkdir()
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True, capture_output=True)
    for k, v in (("user.email", "t@example.invalid"), ("user.name", "test"), ("commit.gpgsign", "false")):
        git(clone, "config", k, v)
    (clone / "README.md").write_text("x\n")
    git(clone, "add", "README.md")
    git(clone, "commit", "-q", "-m", "init")
    git(clone, "push", "-q", "origin", "HEAD:main")
    git(clone, "switch", "-q", "-c", "work")
    git(clone, "push", "-q", "-u", "origin", "work")
    (clone / ".ds-worker.json").write_text("{}\n")
    (clone / ".git" / "info" / "exclude").write_text(".ds-worker.json\n")
    return origin, clone


def make_crlf_phantom(clone: Path, name: str = "LICENSE.md") -> None:
    """Issue #28's shape (app-core's third_party/pftcm/LICENSE.md): a file committed with CRLF,
    then .gitattributes changed to `eol=lf`. Every fresh checkout then shows it modified (` M`) though
    nothing but its line endings differ. Pushed, so the clone is otherwise clean."""
    git(clone, "config", "core.autocrlf", "true")
    (clone / ".gitattributes").write_bytes(b"* -text\n")
    (clone / name).write_bytes(b"line one\r\nline two\r\n")
    git(clone, "add", ".gitattributes", name)
    git(clone, "commit", "-q", "-m", "vendored file with CRLF")
    (clone / ".gitattributes").write_bytes(b"* text eol=lf\n")
    git(clone, "add", ".gitattributes")
    git(clone, "commit", "-q", "-m", "attributes: eol=lf")
    git(clone, "push", "-q", "origin", "HEAD")
    (clone / name).unlink()
    git(clone, "checkout", "-q", "--", name)
    # The checkout records the file's stat in the index. Git compares content (and so sees the line endings)
    # only when that stat no longer matches, or by luck when file and index share a timestamp ("racily
    # clean"): on a fast disk that is every time, on a CI runner only sometimes. Move the mtime so it is always.
    stamp = (clone / name).stat().st_mtime + 10
    os.utime(clone / name, (stamp, stamp))
    assert git(clone, "status", "--porcelain") == f"M {name}"  # the precondition: git calls it modified
