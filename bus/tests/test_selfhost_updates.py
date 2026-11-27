"""The self-hosted automatic updater: release fetcher, on/off switch, console button."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from strugglebus import __version__
from strugglebus.app import create_app
from strugglebus.config import AppConfig
from strugglebus.selfhost_updates import STATUS_FILE, SWITCH_FILE, TOGGLE_PATH, SelfHostUpdates
from test_operator_dashboard import csrf, login, verifier  # noqa: F401 - fixture

KIT = Path(__file__).resolve().parents[1] / "src" / "strugglebus" / "selfhost"
ORIGIN = {"Origin": "https://bus.lan"}

from release_signing import TEST_KEY, statement_for  # noqa: E402

_spec = importlib.util.spec_from_file_location("fetch_release", KIT / "fetch_release.py")
fetch_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch_release)


class _ReleasePage:
    """A stand-in for the public release page, serving one release."""

    def __init__(self, folder: Path, version: str) -> None:
        self.version = version
        self.signed_message: str | None = None
        # The copy of the fetcher these tests load trusts the test key, not the owner's.
        fetch_release.RELEASE_KEYS = (TEST_KEY.blob,)
        self.files: dict[str, bytes] = {}
        self.requested: list[str] = []
        wheel = folder / f"strugglebus-{version}-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("strugglebus/__init__.py", f'__version__ = "{version}"\n')
            archive.writestr("strugglebus/selfhost/fetch_release.py", "# fetcher\n")
            archive.writestr("strugglebus/selfhost/debian/install.sh", "#!/bin/bash\n")
        self.files[wheel.name] = wheel.read_bytes()
        self.files["requirements.lock"] = b"example==1.0 --hash=sha256:00\n"
        self.files["SHA256SUMS"] = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n"
            for name, data in sorted(self.files.items())
        ).encode()
        page = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                page.requested.append(self.path)
                if self.path == "/latest":
                    body = json.dumps({
                        "tag_name": "v" + page.version,
                        "assets": [
                            {"name": name, "browser_download_url": page.base + "/files/" + name}
                            for name in page.files
                        ],
                    }).encode()
                elif self.path == f"/latest/git/ref/tags/v{page.version}":
                    body = json.dumps({"object": {"type": "tag", "sha": "a" * 40}}).encode()
                elif self.path == "/latest/git/tags/" + "a" * 40:
                    body = json.dumps({"tag": "v" + page.version, "message": page.tag_message()}).encode()
                elif self.path.startswith("/files/") and self.path[7:] in page.files:
                    body = page.files[self.path[7:]]
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *arguments: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tag_message(self) -> str:
        """
        The publisher's signed statement. Unless a test fixes it, it is signed afresh for
        whatever the page serves now, so a test that spoils a file is testing the check it
        means to and not the signature in front of it.
        """
        if self.signed_message is not None:
            return self.signed_message
        return TEST_KEY.tag_message(statement_for(self.version, self.files))

    def fetch(self, installed: str, into: Path) -> tuple[str, str]:
        return fetch_release.fetch(
            installed, into, api=self.base + "/latest", download_prefix=self.base + "/files/",
        )


@pytest.fixture
def page(tmp_path: Path):
    served = tmp_path / "served"
    served.mkdir()
    release = _ReleasePage(served, "0.3.0")
    yield release
    release.server.shutdown()
    release.server.server_close()


def test_fetcher_downloads_and_unpacks_a_newer_release(page: _ReleasePage, tmp_path: Path):
    into = tmp_path / "release"

    assert page.fetch("0.2.67", into) == ("ready", "0.3.0")

    assert (into / "strugglebus-0.3.0-py3-none-any.whl").read_bytes() == page.files[
        "strugglebus-0.3.0-py3-none-any.whl"
    ]
    assert (into / "requirements.lock").is_file() and (into / "SHA256SUMS").is_file()
    assert (into / "_wheel/strugglebus/selfhost/debian/install.sh").is_file()
    # Only the install files are unpacked, not the application.
    assert not (into / "_wheel/strugglebus/__init__.py").exists()


@pytest.mark.parametrize("installed", ["0.3.0", "0.3.1", "1.0.0"])
def test_fetcher_downloads_nothing_when_the_release_is_not_newer(
    page: _ReleasePage, tmp_path: Path, installed: str,
):
    into = tmp_path / "release"

    assert page.fetch(installed, into) == ("current", "0.3.0")

    assert not into.exists()
    assert page.requested == ["/latest"]


def test_fetcher_compares_versions_as_numbers_not_text(page: _ReleasePage, tmp_path: Path):
    page.version = "0.10.0"
    with pytest.raises(fetch_release.Problem):
        # 0.10.0 is newer than 0.9.9; it gets as far as the missing 0.10.0 wheel.
        page.fetch("0.9.9", tmp_path / "release")
    assert fetch_release.parse_version("0.10.0") > fetch_release.parse_version("0.9.9")


def test_fetcher_refuses_a_file_that_does_not_match_its_checksum(
    page: _ReleasePage, tmp_path: Path,
):
    page.files["requirements.lock"] = b"tampered==6.6.6\n"

    with pytest.raises(fetch_release.Problem) as raised:
        page.fetch("0.2.67", tmp_path / "release")

    assert raised.value.code == fetch_release.INVALID
    assert "requirements.lock does not match SHA256SUMS" in str(raised.value)


def test_fetcher_refuses_downloads_from_outside_the_release_page(
    page: _ReleasePage, tmp_path: Path,
):
    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release.fetch(
            "0.2.67", tmp_path / "release", api=page.base + "/latest",
            download_prefix=fetch_release.DOWNLOAD_PREFIX,
        )
    assert raised.value.code == fetch_release.INVALID
    # The release page and its signed tag were read; no file was downloaded.
    assert page.requested == ["/latest", "/latest/git/ref/tags/v0.3.0", "/latest/git/tags/" + "a" * 40]


def test_fetcher_reports_an_unreachable_page_and_a_bad_installed_version(tmp_path: Path, capsys):
    code = fetch_release.main([
        "--installed", "0.2.67", "--into", str(tmp_path / "release"),
        "--api", "http://127.0.0.1:9/latest",
    ])
    assert code == fetch_release.UNREACHABLE
    assert "could not download" in capsys.readouterr().err
    assert fetch_release.main(["--installed", "unknown", "--into", str(tmp_path / "x")]) == (
        fetch_release.INVALID
    )


HERE = (fetch_release.API, fetch_release.DOWNLOAD_PREFIX)
FORMER = (fetch_release.FORMER_API, fetch_release.FORMER_DOWNLOAD_PREFIX)
INSTALLED = (0, 2, 72)


def test_fetcher_asks_the_projects_repository_first_and_the_former_place_after():
    assert fetch_release.API == "https://api.github.com/repos/u64a/strugglebus/releases"
    assert fetch_release.DOWNLOAD_PREFIX == "https://github.com/u64a/strugglebus/releases/download/"
    assert fetch_release.TAGS == (
        "https://api.github.com/repos/u64a/strugglebus/git/matching-refs/tags/bus/v?per_page=100"
    )
    assert fetch_release.FORMER_API == (
        "https://api.github.com/repos/NZCypher819/strugglebus-releases/releases/latest"
    )
    assert fetch_release._places(*HERE) == (HERE, FORMER)
    # A mirror the operator set is asked alone.
    assert fetch_release._places("https://mirror.lan/latest", "https://mirror.lan/files/") == (
        ("https://mirror.lan/latest", "https://mirror.lan/files/"),
    )


def _record(tag: str, **more) -> dict:
    return {"tag_name": tag, "assets": [{"name": "a", "browser_download_url": "https://x/" + tag}], **more}


def _tags(*names: str) -> list[dict]:
    return [{"ref": "refs/tags/" + name, "object": {"type": "tag", "sha": "0" * 40}} for name in names]


def _release_address(tag: str) -> str:
    return f"{fetch_release.API}/tags/{tag}"


def _serve(monkeypatch, pages: dict):
    """Answers each address with a page, raises the Problem given for it, or says nothing is there."""
    asked = []

    def read(url: str, limit: int) -> bytes:
        asked.append(url)
        if url not in pages:
            raise fetch_release.Missing(fetch_release.UNREACHABLE, f"could not download {url}: 404")
        page = pages[url]
        if isinstance(page, Exception):
            raise page
        return json.dumps(page).encode()

    monkeypatch.setattr(fetch_release, "_read", read)
    return asked


def test_bus_releases_are_found_by_tag_so_other_releases_cannot_bury_them(monkeypatch):
    """However many App releases are published after it, a bus release is still found."""
    asked = _serve(monkeypatch, {
        fetch_release.TAGS: _tags("bus/v0.2.73", "bus/v0.2.74", "bus/v0.10.0", "bus/v0.9.9"),
        _release_address("bus/v0.10.0"): _record("bus/v0.10.0"),
    })

    release = fetch_release._newest_here(INSTALLED)

    assert (release.tag, release.version) == ("bus/v0.10.0", "0.10.0")
    assert release.assets == {"a": "https://x/bus/v0.10.0"}
    assert (release.api, release.download_prefix) == HERE
    # Two questions, neither of them the shared list of releases.
    assert asked == [fetch_release.TAGS, _release_address("bus/v0.10.0")]


def test_with_no_newer_tag_nothing_more_is_asked(monkeypatch):
    asked = _serve(monkeypatch, {fetch_release.TAGS: _tags("bus/v0.2.71", "bus/v0.2.72")})
    assert fetch_release._newest_here(INSTALLED) is None
    assert asked == [fetch_release.TAGS]

    _serve(monkeypatch, {fetch_release.TAGS: []})
    assert fetch_release._newest_here(INSTALLED) is None


def test_tags_that_are_not_bus_versions_are_not_releases(monkeypatch):
    asked = _serve(monkeypatch, {
        fetch_release.TAGS: _tags("bus/vnext", "bus/v0.3.0-rc1", "bus/v00.3.0", "bus/v0.2.73"),
        _release_address("bus/v0.2.73"): _record("bus/v0.2.73"),
    })

    assert fetch_release._newest_here(INSTALLED).version == "0.2.73"
    assert asked == [fetch_release.TAGS, _release_address("bus/v0.2.73")]


def test_a_newer_tag_with_no_release_does_not_hide_a_real_update(monkeypatch):
    """Anyone who can push can make a tag. Only a published release counts."""
    asked = _serve(monkeypatch, {
        fetch_release.TAGS: _tags("bus/v0.2.73", "bus/v9.9.9", "bus/v9.9.8", "bus/v9.9.7"),
        _release_address("bus/v9.9.8"): _record("bus/v9.9.8", draft=True),
        _release_address("bus/v9.9.7"): _record("bus/v9.9.7", prerelease=True),
        _release_address("bus/v0.2.73"): _record("bus/v0.2.73"),
    })

    assert fetch_release._newest_here(INSTALLED).version == "0.2.73"
    assert asked[1:] == [_release_address(tag) for tag in ("bus/v9.9.9", "bus/v9.9.8", "bus/v9.9.7", "bus/v0.2.73")]


def test_a_release_page_for_another_tag_is_not_taken(monkeypatch):
    _serve(monkeypatch, {
        fetch_release.TAGS: _tags("bus/v0.2.74", "bus/v0.2.73"),
        _release_address("bus/v0.2.74"): _record("bus/v0.2.75"),
        _release_address("bus/v0.2.73"): _record("bus/v0.2.73"),
    })

    assert fetch_release._newest_here(INSTALLED).version == "0.2.73"


def test_only_the_newest_few_tags_are_tried(monkeypatch):
    stray = [f"bus/v9.9.{n}" for n in range(fetch_release.TAGS_TRIED)]
    asked = _serve(monkeypatch, {
        fetch_release.TAGS: _tags("bus/v0.2.73", *stray),
        _release_address("bus/v0.2.73"): _record("bus/v0.2.73"),
    })

    assert fetch_release._newest_here(INSTALLED) is None
    assert len(asked) == 1 + fetch_release.TAGS_TRIED


def _answer(number: int) -> str:
    return fetch_release.TAGS if number == 1 else f"{fetch_release.TAGS}&page={number}"


def test_when_one_answer_cannot_hold_every_tag_the_next_is_asked_for(monkeypatch):
    """Tags come in name order, so the newest can be anywhere, and every answer is read."""
    full = _tags(*(f"bus/v0.1.{n}" for n in range(fetch_release.TAGS_IN_ONE_ANSWER)))
    asked = _serve(monkeypatch, {
        _answer(1): full, _answer(2): full, _answer(3): _tags("bus/v0.2.9", "bus/v0.3.0"),
        _release_address("bus/v0.3.0"): _record("bus/v0.3.0"),
    })

    assert fetch_release._newest_here(INSTALLED).version == "0.3.0"
    assert asked == [_answer(1), _answer(2), _answer(3), _release_address("bus/v0.3.0")]


def test_too_many_tags_to_read_is_a_problem_and_never_nothing_newer(monkeypatch):
    full = _tags(*(f"bus/v0.1.{n}" for n in range(fetch_release.TAGS_IN_ONE_ANSWER)))
    asked = _serve(monkeypatch, {_answer(n): full for n in range(1, fetch_release.TAG_ANSWERS + 1)})

    with pytest.raises(fetch_release.Problem, match="more release tags"):
        fetch_release._newest_here(INSTALLED)

    assert len(asked) == fetch_release.TAG_ANSWERS


@pytest.mark.parametrize("answer", [{"message": "Not Found"}, [{"no": "ref"}], ["text"], "text"])
def test_an_unreadable_tag_list_is_a_problem(monkeypatch, answer):
    _serve(monkeypatch, {fetch_release.TAGS: answer})

    with pytest.raises(fetch_release.Problem, match="release tags could not be read"):
        fetch_release._newest_here(INSTALLED)


@pytest.mark.parametrize("answer", [{"tag_name": "bus/v0.2.73"}, {"tag_name": "bus/v0.2.73", "assets": 7}])
def test_an_unreadable_release_page_is_a_problem(monkeypatch, answer):
    _serve(monkeypatch, {
        fetch_release.TAGS: _tags("bus/v0.2.73"),
        _release_address("bus/v0.2.73"): answer,
    })

    with pytest.raises(fetch_release.Problem, match="did not describe a release"):
        fetch_release._newest_here(INSTALLED)


def test_a_release_that_cannot_be_reached_is_a_problem_not_a_missing_release(monkeypatch):
    down = fetch_release.Problem(fetch_release.UNREACHABLE, "could not download")
    _serve(monkeypatch, {
        fetch_release.TAGS: _tags("bus/v0.2.74", "bus/v0.2.73"),
        _release_address("bus/v0.2.74"): down,
        _release_address("bus/v0.2.73"): _record("bus/v0.2.73"),
    })

    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release._newest_here(INSTALLED)

    assert raised.value is down


def test_a_missing_page_is_told_apart_from_an_unreachable_one(monkeypatch):
    import urllib.error

    def refuse(code):
        def urlopen(request, timeout):
            raise urllib.error.HTTPError(request.full_url, code, "no", {}, None)
        return urlopen

    monkeypatch.setattr(fetch_release.urllib.request, "urlopen", refuse(404))
    with pytest.raises(fetch_release.Missing) as missing:
        fetch_release._read("https://api.github.com/x", 10)
    assert missing.value.code == fetch_release.UNREACHABLE

    monkeypatch.setattr(fetch_release.urllib.request, "urlopen", refuse(403))
    with pytest.raises(fetch_release.Problem) as refused:
        fetch_release._read("https://api.github.com/x", 10)
    assert not isinstance(refused.value, fetch_release.Missing)


def test_a_mirrors_list_counts_only_bus_tags(monkeypatch):
    _serve(monkeypatch, {"list": [
        _record("windows/v9.9.9"), _record("v9.9.8"), _record("bus/v0.3.2", draft=True),
        _record("bus/v0.3.3", prerelease=True), _record("bus/v0.3.1"), _record("bus/v0.10.0"),
        _record("bus/vnext"), "not a record",
    ], "none": [_record("windows/v1.7.3")], "empty": []})

    assert fetch_release._newest_release("list", "p/").version == "0.10.0"
    assert fetch_release._newest_release("none", "p/") is None
    assert fetch_release._newest_release("empty", "p/") is None


def test_a_page_for_one_release_may_use_either_tag_form(monkeypatch):
    _serve(monkeypatch, {"old": _record("v0.2.73"), "new": _record("bus/v0.2.74"), "app": _record("windows/v1.7.3")})

    assert fetch_release._newest_release("old", "p/").version == "0.2.73"
    assert fetch_release._newest_release("new", "p/").version == "0.2.74"
    with pytest.raises(fetch_release.Problem, match="unexpected name"):
        fetch_release._newest_release("app", "p/")


PLACES = (HERE, FORMER)


def _both(here_tags: list[str], former: object) -> dict:
    pages: dict = {fetch_release.TAGS: _tags(*here_tags), fetch_release.FORMER_API: former}
    pages.update({_release_address(tag): _record(tag) for tag in here_tags})
    return pages


def test_the_newest_release_across_both_places_wins(monkeypatch):
    _serve(monkeypatch, _both(["bus/v0.2.74"], _record("v0.2.73")))
    assert fetch_release._newest_anywhere(PLACES, INSTALLED).tag == "bus/v0.2.74"

    _serve(monkeypatch, _both([], _record("v0.2.73")))
    former = fetch_release._newest_anywhere(PLACES, INSTALLED)
    assert (former.tag, former.api, former.download_prefix) == ("v0.2.73", *FORMER)

    # The same version in both places: the first place asked is used.
    _serve(monkeypatch, _both(["bus/v0.2.73"], _record("v0.2.73")))
    assert fetch_release._newest_anywhere(PLACES, INSTALLED).api == fetch_release.API


def test_a_place_that_cannot_be_used_does_not_stop_updates_from_the_other(monkeypatch):
    unreachable = fetch_release.Problem(fetch_release.UNREACHABLE, "could not download")
    asked = _serve(monkeypatch, {fetch_release.TAGS: unreachable, fetch_release.FORMER_API: _record("v0.2.73")})
    assert fetch_release._newest_anywhere(PLACES, INSTALLED).tag == "v0.2.73"
    assert asked == [fetch_release.TAGS, fetch_release.FORMER_API]

    _serve(monkeypatch, {fetch_release.TAGS: {"nonsense": True}, fetch_release.FORMER_API: _record("v0.2.73")})
    assert fetch_release._newest_anywhere(PLACES, INSTALLED).tag == "v0.2.73"

    _serve(monkeypatch, _both(["bus/v0.2.74"], unreachable))
    assert fetch_release._newest_anywhere(PLACES, INSTALLED).tag == "bus/v0.2.74"


def test_when_no_place_answers_the_first_problem_is_reported(monkeypatch):
    first = fetch_release.Problem(fetch_release.UNREACHABLE, "could not download new")
    second = fetch_release.Problem(fetch_release.INVALID, "the release page did not describe a release")
    _serve(monkeypatch, {fetch_release.TAGS: first, fetch_release.FORMER_API: second})

    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release._newest_anywhere(PLACES, INSTALLED)

    assert raised.value is first


def test_with_nothing_published_anywhere_the_bus_is_current(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(fetch_release, "_newest_anywhere", lambda places, installed: None)

    assert fetch_release.fetch("0.2.73", tmp_path / "release", api=HERE[0], download_prefix=HERE[1]) == (
        "current", "0.2.73",
    )
    assert not (tmp_path / "release").exists()


def test_switch_is_on_until_turned_off_and_the_updater_reads_one_word(tmp_path: Path):
    updates = SelfHostUpdates.for_install(tmp_path / "data")
    assert updates.available() is False
    assert updates.enabled() is True and updates.last_check() is None
    (tmp_path / "data" / "selfhost").mkdir(parents=True)

    updates.set_enabled(False)
    assert updates.available() is True
    assert (tmp_path / "data" / SWITCH_FILE).read_bytes() == b"off\n"
    assert updates.enabled() is False

    updates.set_enabled(True)
    assert (tmp_path / "data" / SWITCH_FILE).read_bytes() == b"on\n"
    assert updates.enabled() is True


@pytest.mark.parametrize("content", [b"", b"not json", b"[]", b'{"result": "current"}', b"x" * 20000])
def test_unreadable_status_is_treated_as_no_check(tmp_path: Path, content: bytes):
    (tmp_path / "selfhost").mkdir()
    (tmp_path / STATUS_FILE).write_bytes(content)
    assert SelfHostUpdates.for_install(tmp_path).last_check() is None


@pytest.fixture
def selfhosted(app_config: AppConfig, monkeypatch, verifier, tmp_path: Path):  # noqa: F811
    # What the installer leaves behind: the switch file, turned on.
    switch = app_config.data_dir / SWITCH_FILE
    switch.parent.mkdir(parents=True)
    switch.write_bytes(b"on\n")
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        yield client, app_config.data_dir / STATUS_FILE, switch


def test_console_button_turns_automatic_updates_off_and_on(selfhosted):
    client, status, switch = selfhosted
    login(client)

    page = client.get("/operator/updates")
    assert page.status_code == 200
    assert "Turn automatic updates off" in page.text
    assert f"Installed version</dt><dd>{__version__}" in page.text
    assert "No check has been recorded yet" in page.text
    # The prepare-only workflow of the managed deployment is not offered here.
    assert "protected worker socket" not in page.text

    off = client.post(TOGGLE_PATH, data={"csrf": csrf(page), "enabled": "false"}, headers=ORIGIN)
    assert off.status_code == 303 and off.headers["location"] == "/operator/updates"
    assert switch.read_bytes() == b"off\n"

    status.write_text(json.dumps({
        "checked_at": 1795000000, "auto_update": "off", "result": "off",
        "installed_version": __version__, "latest_version": "",
        "detail": "<b>Automatic updates are turned off.</b>",
    }), encoding="utf-8")
    page = client.get("/operator/updates")
    assert "Turn automatic updates on" in page.text
    assert "Not checked: automatic updates are off" in page.text
    assert "&lt;b&gt;Automatic updates are turned off.&lt;/b&gt;" in page.text

    on = client.post(TOGGLE_PATH, data={"csrf": csrf(page), "enabled": "true"}, headers=ORIGIN)
    assert on.status_code == 303
    assert switch.read_bytes() == b"on\n"


def test_switch_needs_a_signed_in_operator_and_a_valid_form(selfhosted):
    client, _status, switch = selfhosted
    anonymous = client.post(TOGGLE_PATH, data={"csrf": "x", "enabled": "false"}, headers=ORIGIN)
    assert anonymous.status_code in {303, 401, 403}

    login(client)
    page = client.get("/operator/updates")
    for data in ({"csrf": "wrong", "enabled": "false"}, {"csrf": csrf(page), "enabled": "maybe"}):
        refused = client.post(TOGGLE_PATH, data=data, headers=ORIGIN)
        assert refused.status_code in {400, 403}, refused.text
    assert switch.read_bytes() == b"on\n"


def test_install_without_an_updater_has_no_switch(app_config: AppConfig, monkeypatch, verifier):  # noqa: F811
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        login(client)
        page = client.get("/operator/updates")
        assert "Turn automatic updates" not in page.text
        refused = client.post(
            TOGGLE_PATH, data={"csrf": csrf(client.get("/register")), "enabled": "false"},
            headers=ORIGIN,
        )
        assert refused.status_code == 400
        assert not (app_config.data_dir / SWITCH_FILE).exists()


def test_installer_sets_up_the_updater_and_keeps_the_setting_on_upgrade():
    installer = (KIT / "debian" / "install.sh").read_text(encoding="utf-8")
    # No setting: the managed deployment's unit must not need to know about this.
    assert "SELFHOST_UPDATE" not in installer
    assert "SELFHOST_UPDATE" not in (KIT.parent / "config.py").read_text(encoding="utf-8")
    assert "systemctl enable --quiet --now strugglebus-update.timer" in installer
    # An upgrade only writes the setting when asked to or when there is none.
    assert 'elif ! runuser -u strugglebus -- test -e "$UPDATE_SWITCH"; then' in installer
    updater = (KIT / "debian" / "strugglebus-update").read_text(encoding="utf-8")
    assert "/var/lib/strugglebus/selfhost/auto-update" in updater
    assert "/var/lib/strugglebus/selfhost/update-status.json" in updater
    assert STATUS_FILE.as_posix() == "selfhost/update-status.json"
    assert SWITCH_FILE.as_posix() == "selfhost/auto-update"
    for script in (updater, (KIT / "docker" / "update.sh").read_text(encoding="utf-8")):
        # Replaced while running, so the body must be parsed before it starts.
        assert script.rstrip().endswith('main "$@"\nexit 0')
        assert "selfhost/auto-update" in script
    entrypoint = (KIT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    assert 'echo on > "$STRUGGLEBUS_DATA_DIR/selfhost/auto-update"' in entrypoint
    timer = (KIT / "debian" / "strugglebus-update.timer").read_text(encoding="utf-8")
    assert "Persistent=true" in timer
