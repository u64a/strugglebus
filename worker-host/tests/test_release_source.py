"""Where releases come from (workerhost/update.py): a release repository of its own
with the code in a folder, and the signed redirect (moved_to) with the security review's rules:
(a) the source moves, never the trust; (b) the rollback guard survives; (c) only main is fetched; (d) one hop, no
fallback to the old source; (e) the source is in the status."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from test_update import COMMIT, FILES, installed_app, keygen, release_toml, uhost  # noqa: F401 (fixtures)
from workerhost import hoststatus, update

MOVED = '\n[moved_to]\nrepo = "https://github.com/u64a/strugglebus"\npath = "worker-host"\n'


# --- (a) the redirect's shape: the source only, never the trust ---------------------------------------------------

def test_a_redirect_parses():
    rel = update.parse_release(release_toml(extra=MOVED))
    assert rel.moved_to == ("https://github.com/u64a/strugglebus", "worker-host")
    assert update.parse_release(release_toml()).moved_to is None


@pytest.mark.parametrize("table", [
    '[moved_to]\nrepo = "https://github.com/u64a/strugglebus"\npath = "worker-host"\nkey = "ssh-ed25519 AAAA"\n',
    '[moved_to]\nrepo = "https://github.com/u64a/strugglebus"\npath = "worker-host"\nsigner = "evil"\n',
    '[moved_to]\nrepo = "https://github.com/u64a/strugglebus"\n',                      # no path
    '[moved_to]\nrepo = "http://github.com/u64a/strugglebus"\npath = ""\n',           # not https
    '[moved_to]\nrepo = "https://github.com/u64a/strugglebus.git"\npath = ""\n',
    '[moved_to]\nrepo = "https://github.com/u64a"\npath = ""\n',                      # not a repository
    '[moved_to]\nrepo = "https://github.com/u64a/strugglebus"\npath = "../escape"\n',
    '[moved_to]\nrepo = "https://github.com/u64a/strugglebus"\npath = "a/./b"\n',
    '[moved_to]\nrepo = "https://github.com/u64a/strugglebus"\npath = "/abs"\n',
])
def test_a_redirect_that_names_anything_else_or_points_badly_is_refused(table):
    with pytest.raises(update.ReleaseError) as e:
        update.parse_release(release_toml(extra="\n" + table))
    assert e.value.reason == "release-invalid" and "moved_to" in e.value.detail


def test_a_redirect_only_into_the_hosts_remotes():
    rel = update.parse_release(release_toml(extra=MOVED))
    assert update.redirect_allowed(rel, ["https://github.com/u64a/"])
    assert update.redirect_allowed(rel, ["https://github.com/"])
    assert not update.redirect_allowed(rel, ["https://github.com/acme/"])
    assert not update.redirect_allowed(rel, ["https://github.com/u64a-evil/"])
    assert update.redirect_allowed(update.parse_release(release_toml()), [])  # no redirect: nothing to fence


# --- recorded only by installing; a rollback takes it away (d) ----------------------------------------------------

def test_the_redirect_is_recorded_by_installing_and_removed_by_a_rollback(tmp_path):
    app, backup = installed_app(tmp_path), tmp_path / "app.prev"
    update.apply_files(FILES, app, backup, update.parse_release(release_toml(extra=MOVED)))
    assert update.installed(app)["moved_to"] == ("https://github.com/u64a/strugglebus", "worker-host")
    assert update.restore(app, backup)
    assert update.installed(app)["moved_to"] is None


def test_a_hand_edited_redirect_in_release_json_is_not_trusted(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / update.INSTALLED).write_text(json.dumps({"version": "x", "serial": 3, "commit": COMMIT, "moved_to": {
        "repo": "https://github.com/u64a/strugglebus", "path": "worker-host", "key": "AAAA"}}), encoding="utf-8")
    assert update.installed(app)["moved_to"] is None and update.installed(app)["serial"] == 3


def test_an_installed_redirect_outside_the_remotes_is_not_used(tmp_path):
    """RELEASE.json is writable by the host's account, so a well-formed hand-written redirect is fenced again
    (security review)."""
    app = tmp_path / "app"
    app.mkdir()
    (app / update.INSTALLED).write_text(json.dumps({"version": "x", "serial": 5, "commit": COMMIT, "moved_to": {
        "repo": "https://github.com/someone-else/fork", "path": "worker-host"}}), encoding="utf-8")
    inst = update.installed(app)
    assert inst["moved_to"] == ("https://github.com/someone-else/fork", "worker-host")  # well-formed
    cfg = NS(release_remote=lambda: "", release_path="", remotes=["https://github.com/u64a/"])
    w = update.where(cfg, inst)
    assert (w.origin, w.url, w.refused) == ("fleet", "", "https://github.com/someone-else/fork")
    ok = update.where(NS(release_remote=lambda: "", release_path="", remotes=["https://github.com/someone-else/"]),
                      inst)
    assert (ok.origin, ok.refused) == ("redirect", "")


def test_a_refused_installed_redirect_is_shown_as_a_problem(uhost, monkeypatch):  # noqa: F811
    from workerhost import engines

    monkeypatch.setattr(engines, "resolve", lambda name: "C:\\bin\\copilot.exe")
    uhost.release_where = update.Where("", "", "fleet", refused="https://github.com/someone-else/fork")
    status = hoststatus.build(uhost.status_facts())
    assert status["problem"]["code"] == "release-redirect-refused" and status["release"]["source"] == "fleet"


def test_an_edited_mirror_fetch_setting_does_not_persist(monorepo):
    """The mirror is in writable state: a widened refspec is put back before every fetch (security review)."""
    mirror = update.mirror_for(monorepo.tmp / "mirrors", monorepo.url)
    assert update.fetch_release_mirror("git", mirror, monorepo.url)
    subprocess.run(["git", "--git-dir", str(mirror), "config", "remote.origin.fetch", "+refs/*:refs/*"], check=True)
    subprocess.run(["git", "--git-dir", str(mirror), "config", "remote.origin.url", "https://evil.example/x/y"],
                   check=True)
    assert update.fetch_release_mirror("git", mirror, monorepo.url)
    refs = subprocess.run(["git", "--git-dir", str(mirror), "for-each-ref", "--format=%(refname)"],
                          capture_output=True, text=True).stdout.split()
    assert not any("pull" in r for r in refs)
    cfg = lambda key: subprocess.run(["git", "--git-dir", str(mirror), "config", "--get-all", key],  # noqa: E731
                                     capture_output=True, text=True).stdout.split()
    assert cfg("remote.origin.fetch") == ["+refs/heads/main:refs/remotes/origin/main"]
    assert cfg("remote.origin.url") == [monorepo.url]


@pytest.mark.parametrize("cfg_url, inst_moved, expected", [
    ("", None, ("", "", "fleet")),
    ("", ("https://github.com/u64a/strugglebus", "worker-host"),
     ("https://github.com/u64a/strugglebus", "worker-host", "redirect")),
    ("https://example.lan/x/y.git", ("https://github.com/u64a/strugglebus", "worker-host"),
     ("https://example.lan/x/y.git", "", "config")),  # an administrator's explicit setting wins
])
def test_where_releases_come_from(cfg_url, inst_moved, expected):
    cfg = NS(release_remote=lambda: cfg_url, release_path="", remotes=["https://github.com/u64a/"])
    w = update.where(cfg, {"moved_to": inst_moved})
    assert (w.url, w.path, w.origin) == expected
    assert w.label() == ("fleet" if expected[2] == "fleet" else expected[0] + (f"#{expected[1]}" if expected[1] else ""))


# --- the code in a folder, from a mirror of main only (c) ---------------------------------------------------------

def git(work: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(work), "-c", "user.email=t@x", "-c", "user.name=t", *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def monorepo(tmp_path, keygen):  # noqa: F811
    """A monorepo-like origin: other products at the top, the host in worker-host/, a signed release there, and a
    pull request ref that must never reach a host."""
    keys = tmp_path / "keys"
    keys.mkdir()
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", "alice", "-f", str(keys / "alice")], check=True,
                   capture_output=True)
    pub = (keys / "alice.pub").read_text().split()
    (keys / "allowed_signers").write_text(f'alice namespaces="strugglebus-release" {pub[0]} {pub[1]}\n')
    origin = tmp_path / "origin"
    subprocess.run(["git", "init", "-q", "-b", "main", str(origin)], check=True)
    git(origin, "config", "uploadpack.allowFilter", "true")
    (origin / "bus").mkdir()
    (origin / "bus" / "big.bin").write_bytes(b"\0" * 200_000)  # someone else's product: never needed by a host
    update.write_files(FILES, origin / "worker-host")
    git(origin, "add", "-A")
    git(origin, "commit", "-q", "-m", "code")
    code = git(origin, "rev-parse", "HEAD")
    data = release_toml(serial=6, commit=code)
    (origin / "worker-host" / "release.toml").write_bytes(data)
    msg = tmp_path / "msg"
    msg.write_bytes(data)
    subprocess.run([keygen, "-Y", "sign", "-f", str(keys / "alice"), "-n", "strugglebus-release", str(msg)],
                   check=True, capture_output=True)
    (origin / "worker-host" / "release.toml.sig").write_bytes(Path(str(msg) + ".sig").read_bytes())
    git(origin, "add", "-A")
    git(origin, "commit", "-q", "-m", "release")
    git(origin, "update-ref", "refs/pull/1/head", code)  # what GitHub exposes for every pull request
    return NS(url=origin.as_uri(), code=code, signers=keys / "allowed_signers", keygen=keygen, tmp=tmp_path)


def test_a_release_is_read_from_a_folder_with_the_same_tree_hash(monorepo):
    mirror = update.mirror_for(monorepo.tmp / "mirrors", monorepo.url)
    assert update.fetch_release_mirror("git", mirror, monorepo.url)
    src = update.ReleaseSource(mirror, "git", monorepo.keygen, monorepo.signers, monorepo.tmp / "rt",
                               path="worker-host")
    rel, status = src.read()
    assert status == "ok" and rel.serial == 6
    assert src.files(rel) == FILES  # paths relative to the folder: the same tree hash as at the top level
    assert update.tree_sha256(src.files(rel)) == update.tree_sha256(FILES)


def test_only_main_is_fetched_never_a_pull_request_ref(monorepo):
    mirror = update.mirror_for(monorepo.tmp / "mirrors", monorepo.url)
    assert update.fetch_release_mirror("git", mirror, monorepo.url)
    refs = subprocess.run(["git", "--git-dir", str(mirror), "for-each-ref", "--format=%(refname)"],
                          capture_output=True, text=True).stdout.split()
    assert "refs/remotes/origin/main" in refs
    assert not any("pull" in r for r in refs) and set(refs) <= {"refs/remotes/origin/main", "refs/remotes/origin/HEAD"}
    cfg = subprocess.run(["git", "--git-dir", str(mirror), "config", "remote.origin.partialclonefilter"],
                         capture_output=True, text=True).stdout.strip()
    assert cfg == "blob:none"


def test_a_mirror_per_repository_url(tmp_path):
    a = update.mirror_for(tmp_path, "https://github.com/u64a/strugglebus")
    assert a == update.mirror_for(tmp_path, "https://github.com/u64a/strugglebus")
    assert a != update.mirror_for(tmp_path, "https://github.com/u64a/other")


def test_an_unreachable_repository_fails_cleanly(tmp_path):
    assert not update.fetch_release_mirror("git", tmp_path / "m.git", (tmp_path / "nowhere").as_uri())


# --- the host: no fallback (d), the rollback guard (b), the fence, the status (e) -----------------------------------

def redirected(h, url="https://github.com/u64a/strugglebus", path="worker-host"):
    h.release_where = update.Where(url, path, "redirect")


def test_an_unreachable_new_source_keeps_the_host_where_it_is_and_says_so(uhost, monkeypatch):  # noqa: F811
    from workerhost import engines

    # Copilot CLI counts as installed here, so the problem shown does not depend on the machine (CI has none).
    monkeypatch.setattr(engines, "resolve", lambda name: "C:\\bin\\copilot.exe")
    redirected(uhost)
    monkeypatch.setattr(update, "fetch_release_mirror", lambda *a, **k: False)
    read = []
    uhost.release_source.read = lambda: read.append(1) or (None, "release-missing")
    assert uhost.update_check() is None
    assert read == []  # nothing read: not the stale copy, and never the old source
    status = hoststatus.build(uhost.status_facts())
    assert status["problem"]["code"] == "release-source-unreachable"
    assert status["release"]["source"] == "https://github.com/u64a/strugglebus#worker-host"


def test_an_older_signed_release_at_the_new_source_is_never_applied(uhost, monkeypatch):  # noqa: F811
    """(b) The installed serial is host state; a redirect does not reset it."""
    redirected(uhost)
    monkeypatch.setattr(update, "fetch_release_mirror", lambda *a, **k: True)
    inst = update.installed(uhost.app_dir)
    update.apply_files(FILES, uhost.app_dir, uhost.app_dir.parent / "prev",
                       update.parse_release(release_toml(serial=5, commit="b" * 40)))
    old = update.parse_release(release_toml(serial=4))
    uhost.release_source.rel = old
    assert uhost.update_check() == old
    assert uhost.ustate.get("phase") != "announced" and inst  # read, compared, not applied


def test_a_redirect_outside_the_remotes_is_refused_and_not_applied(uhost, monkeypatch):  # noqa: F811
    uhost.cfg.remotes = ["https://github.com/acme/"]
    uhost.release_source.rel = update.parse_release(release_toml(serial=9, extra=MOVED))
    assert uhost.update_check() is None
    assert uhost.ustate.get("phase") != "announced"


def test_the_fleet_source_is_the_default_and_shows_as_such(uhost):  # noqa: F811
    assert uhost.release_where.origin == "fleet"
    assert hoststatus.build(uhost.status_facts())["release"]["source"] == "fleet"
