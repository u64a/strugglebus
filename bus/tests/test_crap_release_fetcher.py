"""Refusal paths and the command-line contract of the standalone release fetcher."""

from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from test_selfhost_updates import KIT, _ReleasePage, fetch_release

WHEEL = "strugglebus-0.3.0-py3-none-any.whl"


@pytest.fixture
def page(tmp_path: Path):
    served = tmp_path / "served"
    served.mkdir()
    release = _ReleasePage(served, "0.3.0")
    yield release
    release.server.shutdown()
    release.server.server_close()


def relist(page: _ReleasePage, *, binary: bool = False) -> None:
    """Rewrite SHA256SUMS so it matches whatever the page now serves."""
    separator = " *" if binary else "  "
    page.files["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(data).hexdigest()}{separator}{name}\n"
        for name, data in sorted(page.files.items()) if name != "SHA256SUMS"
    ).encode()


def refusal(page: _ReleasePage, into: Path) -> fetch_release.Problem:
    with pytest.raises(fetch_release.Problem) as raised:
        page.fetch("0.2.67", into)
    return raised.value


@pytest.mark.parametrize("described", [
    b"not json",
    b"[]",
    b"{}",
    b'{"tag_name": "v0.3.0"}',
    b'{"tag_name": "v0.3.0", "assets": [{"name": "SHA256SUMS"}]}',
    b'{"tag_name": "v0.3.0", "assets": 7}',
])
def test_page_that_does_not_describe_a_release_is_refused(page, tmp_path, described):
    page.files["latest.json"] = described
    into = tmp_path / "release"

    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release.fetch(
            "0.2.67", into, api=page.base + "/files/latest.json",
            download_prefix=page.base + "/files/",
        )

    assert raised.value.code == fetch_release.INVALID
    assert str(raised.value) == "the release page did not describe a release"
    assert not into.exists()


@pytest.mark.parametrize("tag", ['"0.3.0"', '"release-0.3.0"', "3", "null"])
def test_release_with_an_unexpected_name_is_refused(page, tmp_path, tag):
    page.files["latest.json"] = ('{"tag_name": %s, "assets": []}' % tag).encode()

    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release.fetch(
            "0.2.67", tmp_path / "release", api=page.base + "/files/latest.json",
            download_prefix=page.base + "/files/",
        )

    assert raised.value.code == fetch_release.INVALID
    assert str(raised.value) == "the newest release has an unexpected name"


def test_release_tag_that_is_not_a_version_is_refused(page, tmp_path):
    page.version = "0.3.0-rc1"

    problem = refusal(page, tmp_path / "release")

    assert problem.code == fetch_release.INVALID
    assert "is not a release version" in str(problem)


@pytest.mark.parametrize("missing", ["SHA256SUMS", "requirements.lock", WHEEL])
def test_release_missing_a_needed_file_downloads_nothing(page, tmp_path, missing):
    del page.files[missing]
    into = tmp_path / "release"

    problem = refusal(page, into)

    assert problem.code == fetch_release.INVALID
    assert str(problem) == f"release v0.3.0 has no usable {missing}"
    assert not into.exists()
    assert page.requested == ["/latest"]


def test_existing_destination_is_never_reused(page, tmp_path):
    into = tmp_path / "release"
    into.mkdir()

    with pytest.raises(FileExistsError):
        page.fetch("0.2.67", into)

    assert list(into.iterdir()) == []
    assert page.requested == ["/latest"]


def test_wheel_that_does_not_match_its_checksum_is_refused(page, tmp_path):
    page.files[WHEEL] += b"appended"

    problem = refusal(page, tmp_path / "release")

    assert problem.code == fetch_release.INVALID
    assert str(problem) == f"{WHEEL} does not match SHA256SUMS in release v0.3.0"
    assert not (tmp_path / "release" / "_wheel").exists()


def test_file_absent_from_the_checksum_list_is_refused(page, tmp_path):
    digest = hashlib.sha256(page.files[WHEEL]).hexdigest()
    page.files["SHA256SUMS"] = f"{digest}  {WHEEL}\n".encode()

    problem = refusal(page, tmp_path / "release")

    assert str(problem) == "requirements.lock does not match SHA256SUMS in release v0.3.0"


def test_binary_mode_and_uppercase_checksum_lines_are_accepted(page, tmp_path):
    relist(page, binary=True)
    page.files["SHA256SUMS"] = page.files["SHA256SUMS"].decode().replace(
        hashlib.sha256(page.files[WHEEL]).hexdigest(),
        hashlib.sha256(page.files[WHEEL]).hexdigest().upper(),
    ).encode()

    assert page.fetch("0.2.67", tmp_path / "release") == ("ready", "0.3.0")


def test_wheel_that_is_not_an_archive_is_refused_after_its_checksum_passes(page, tmp_path):
    page.files[WHEEL] = b"this is not a zip archive"
    relist(page)

    problem = refusal(page, tmp_path / "release")

    assert problem.code == fetch_release.INVALID
    assert str(problem).startswith(f"{WHEEL} could not be opened: ")


def test_wheel_without_the_install_files_is_refused(page, tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("strugglebus/__init__.py", "")
        archive.writestr("strugglebus/selfhost/debian/install.sh", "#!/bin/bash\n")
    page.files[WHEEL] = data.getvalue()
    relist(page)

    problem = refusal(page, tmp_path / "release")

    assert problem.code == fetch_release.INVALID
    assert str(problem) == "release v0.3.0 does not carry the install files"


@pytest.mark.parametrize("url", [
    "http://example.com/latest", "ftp://127.0.0.1/latest", "file:///etc/passwd",
    "http://127.0.0.1.example.com:80/latest", "http://localhost/latest",
])
def test_plain_or_foreign_addresses_are_never_requested(url):
    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release._read(url, 10)

    assert raised.value.code == fetch_release.INVALID
    assert str(raised.value) == f"refusing to download from {url}"


def test_oversized_download_is_refused_and_one_at_the_limit_is_kept(page):
    page.files["blob"] = b"x" * 11
    url = page.base + "/files/blob"

    assert fetch_release._read(url, 11) == b"x" * 11
    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release._read(url, 10)

    assert raised.value.code == fetch_release.INVALID
    assert str(raised.value) == f"{url} is larger than expected"


def test_missing_page_is_reported_as_unreachable(page):
    with pytest.raises(fetch_release.Problem) as raised:
        fetch_release._read(page.base + "/files/absent", 10)

    assert raised.value.code == fetch_release.UNREACHABLE


def test_main_prints_one_result_line_and_exits_zero(page, tmp_path, capsys):
    arguments = ["--api", page.base + "/latest", "--download-prefix", page.base + "/files/"]

    assert fetch_release.main(
        ["--installed", "0.3.0", "--into", str(tmp_path / "unused"), *arguments]
    ) == 0
    assert capsys.readouterr().out == "current 0.3.0\n"

    assert fetch_release.main(
        ["--installed", "0.2.67", "--into", str(tmp_path / "release"), *arguments]
    ) == 0
    assert capsys.readouterr().out == "ready 0.3.0\n"
    assert (tmp_path / "release" / "_wheel/strugglebus/selfhost/fetch_release.py").is_file()


def test_main_reports_a_failed_check_on_standard_error_with_exit_four(page, tmp_path, capsys):
    page.files["requirements.lock"] = b"tampered==6.6.6\n"

    code = fetch_release.main([
        "--installed", "0.2.67", "--into", str(tmp_path / "release"),
        "--api", page.base + "/latest", "--download-prefix", page.base + "/files/",
    ])

    captured = capsys.readouterr()
    assert code == fetch_release.INVALID == 4
    assert captured.out == ""
    assert captured.err == (
        "fetch_release: requirements.lock does not match SHA256SUMS in release v0.3.0\n"
    )


def run_script(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the fetcher the way the updaters do: a bare interpreter, no project on the path."""
    return subprocess.run(  # noqa: S603 - fixed interpreter and script
        [sys.executable, "-I", "-S", str(KIT / "fetch_release.py"), *arguments],
        capture_output=True, text=True, timeout=120, check=False,
    )


def test_script_runs_standalone_with_only_the_standard_library(page, tmp_path):
    into = tmp_path / "release"
    served = ["--api", page.base + "/latest", "--download-prefix", page.base + "/files/"]

    current = run_script("--installed", "0.3.0", "--into", str(into), *served)
    assert (current.returncode, current.stdout, current.stderr) == (0, "current 0.3.0\n", "")
    assert not into.exists()

    ready = run_script("--installed", "0.2.67", "--into", str(into), *served)
    assert (ready.returncode, ready.stdout, ready.stderr) == (0, "ready 0.3.0\n", "")
    assert sorted(item.name for item in into.iterdir()) == [
        "SHA256SUMS", "_wheel", "requirements.lock", WHEEL,
    ]


def test_script_exit_codes_for_invalid_and_unreachable_releases(page, tmp_path):
    page.files["requirements.lock"] = b"tampered==6.6.6\n"

    invalid = run_script(
        "--installed", "0.2.67", "--into", str(tmp_path / "a"),
        "--api", page.base + "/latest", "--download-prefix", page.base + "/files/",
    )
    unreachable = run_script(
        "--installed", "0.2.67", "--into", str(tmp_path / "b"),
        "--api", "http://127.0.0.1:9/latest",
    )

    assert invalid.returncode == 4 and invalid.stdout == ""
    assert invalid.stderr.startswith("fetch_release: requirements.lock does not match")
    assert unreachable.returncode == 3 and unreachable.stdout == ""
    assert unreachable.stderr.startswith("fetch_release: could not download ")
