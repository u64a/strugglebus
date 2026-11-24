"""Exact refusals, and their order, in the release identity, URL and wheel checks."""

from __future__ import annotations

import zipfile

import pytest

from strugglebus import release_transport as transport
from strugglebus import release_validation as validation
from strugglebus import release_wheel as wheel

REPOSITORY = "NZCypher819/strugglebus-releases"
COMMIT, TREE = "a" * 40, "b" * 40
HOSTS = frozenset({"api.github.com", "uploads.github.com"})


def release(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "repository": REPOSITORY, "tag": "v1.2.3", "source_commit": COMMIT, "source_tree": TREE,
    }
    value.update({key: item for key, item in changes.items() if key != "candidate_id"})
    value["candidate_id"] = changes.get(
        "candidate_id",
        f"{value['repository']}@{value['tag']}:{value['source_commit']}:{value['source_tree']}",
    )
    return value


def validate_source(value: dict[str, object], *, version: str = "1.2.3",
                    repository: str = REPOSITORY, tag: str | None = None,
                    commit: str | None = None, tree: str | None = None):
    return validation._validate_source(value, version, repository, tag, commit, tree)


def test_source_identity_is_returned_with_and_without_pinned_expectations():
    assert validate_source(release()) == ("v1.2.3", COMMIT, TREE)
    assert validate_source(release(), tag="v1.2.3", commit=COMMIT, tree=TREE) == (
        "v1.2.3", COMMIT, TREE,
    )


@pytest.mark.parametrize("pinned,message", [
    ({"tag": "v1.2.4"}, "release tag mismatch"),
    ({"commit": "c" * 40}, "release source commit mismatch"),
    ({"tree": "c" * 40}, "release source tree mismatch"),
    ({"tag": "v9.9.9", "commit": "c" * 40, "tree": "c" * 40}, "release tag mismatch"),
    ({"commit": "c" * 40, "tree": "c" * 40}, "release source commit mismatch"),
])
def test_source_must_match_each_pinned_identity_in_order(pinned, message):
    with pytest.raises(validation.ReleaseBundleError) as raised:
        validate_source(release(), **pinned)
    assert str(raised.value) == message


@pytest.mark.parametrize("value,arguments,message", [
    (release(candidate_id="someone/else@v1.2.3:" + COMMIT + ":" + TREE), {},
     "release candidate identity is inconsistent"),
    (release(), {"repository": "someone/else"}, "release repository identity mismatch"),
    (release(), {"version": "1.2.4"}, "release tag and package version differ"),
    (release(tag="1.2.3"), {}, "release tag has an invalid format"),
    (release(source_commit="A" * 40), {}, "source commit has an invalid format"),
    (release(source_tree="b" * 39), {}, "source tree has an invalid format"),
    (release(repository=""), {}, "release repository is not a bounded non-empty string"),
    (release(candidate_id="x" * 257), {}, "release candidate is not a bounded non-empty string"),
])
def test_source_identity_refusals(value, arguments, message):
    with pytest.raises(validation.ReleaseBundleError) as raised:
        validate_source(value, **arguments)
    assert str(raised.value) == message


def test_source_self_consistency_is_checked_before_any_expectation():
    inconsistent = release(candidate_id="forged")
    with pytest.raises(validation.ReleaseBundleError, match="candidate identity is inconsistent"):
        validate_source(inconsistent, repository="someone/else", tag="v9.9.9")
    with pytest.raises(validation.ReleaseBundleError, match="repository identity mismatch"):
        validate_source(release(), repository="someone/else", version="9.9.9", tag="v9.9.9")
    with pytest.raises(validation.ReleaseBundleError, match="tag and package version differ"):
        validate_source(release(), version="9.9.9", tag="v9.9.9")


def test_source_rejects_missing_or_extra_fields():
    extra = release()
    extra["signature"] = "unexpected"
    missing = release()
    del missing["source_tree"]
    for value in (extra, missing):
        with pytest.raises(validation.ReleaseBundleError):
            validate_source(value)


def write_metadata(path, text: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("strugglebus-1.2.3.dist-info/METADATA", text)


def test_wheel_metadata_reports_what_the_manifest_records(tmp_path):
    path = tmp_path / "strugglebus-1.2.3-py3-none-any.whl"
    write_metadata(path, "Name: strugglebus\nVersion: 1.2.3\nRequires-Python: <3.14,>=3.13\n")

    assert validation._wheel_metadata(path) == {
        "Name": "strugglebus", "Version": "1.2.3", "Requires-Python": "<3.14,>=3.13",
    }
    assert validation._wheel_metadata(path, ">=3.13,<3.14")["Requires-Python"] == "<3.14,>=3.13"


@pytest.mark.parametrize("text,contract,message", [
    ("Name: strugglebus\nVersion: 1.2.3\n", None, "wheel metadata has unexpected Requires-Python"),
    ("Name: strugglebus\nVersion: 1.2.3\nRequires-Python: >=3.8\n", None,
     "wheel metadata has unexpected Requires-Python"),
    ("Name: strugglebus\nVersion: 1.2.3\n", ">=3.12,<3.14",
     "wheel metadata has unexpected Requires-Python"),
    ("Name: other\nVersion: 1.2.3\n", None, "wheel metadata has unexpected Name"),
    ("Name: strugglebus\nVersion: 1.2.4\nRequires-Python: <3.14,>=3.12\n", None,
     "wheel metadata has unexpected Version"),
])
def test_wheel_metadata_refusals_name_the_first_unexpected_field(tmp_path, text, contract, message):
    path = tmp_path / "strugglebus-1.2.3-py3-none-any.whl"
    write_metadata(path, text)

    with pytest.raises(validation.ReleaseBundleError) as raised:
        validation._wheel_metadata(path, contract)
    assert str(raised.value) == message


def test_wheel_metadata_archive_refusals(tmp_path):
    path = tmp_path / "strugglebus-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.dist-info/METADATA", "Name: strugglebus\n")
        archive.writestr("b.dist-info/METADATA", "Name: strugglebus\n")
    with pytest.raises(validation.ReleaseBundleError, match="exactly one METADATA file"):
        validation._wheel_metadata(path)

    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.dist-info/METADATA", b"x" * (validation.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(validation.ReleaseBundleError, match="METADATA exceeds its size limit"):
        validation._wheel_metadata(path)

    other = tmp_path / "strugglebus-1.2.3-cp313-none-any.whl"
    write_metadata(other, "Name: strugglebus\nVersion: 1.2.3\nRequires-Python: <3.14,>=3.12\n")
    with pytest.raises(validation.ReleaseBundleError, match="canonical pure-Python name"):
        validation._wheel_metadata(other)


def exact_host(url: object) -> str:
    return transport._exact_https_host(url, allowed_hosts=HOSTS, error_message="refused url")


@pytest.mark.parametrize("url,host", [
    ("https://api.github.com/repos", "api.github.com"),
    ("HTTPS://API.GitHub.com:443/repos?page=2", "api.github.com"),
    ("https://uploads.github.com/", "uploads.github.com"),
])
def test_exact_host_is_returned_casefolded_for_plain_https(url, host):
    assert exact_host(url) == host


@pytest.mark.parametrize("url", [
    "http://api.github.com/repos",
    "https://api.github.com",
    "https:///repos",
    "https:/repos",
    "https://user@api.github.com/repos",
    "https://user:secret@api.github.com/repos",
    "https://:secret@api.github.com/repos",
    "https://api.github.com:8443/repos",
    "https://api.github.com:0/repos",
    "https://api.github.com:port/repos",
    "https://api.github.com:99999/repos",
    "https://api.github.com.evil.example/repos",
    "https://evil.example/api.github.com",
    "https://[::1/repos",
    "https://api.github.com/repos#fragment",
    "https://api.github.com/re pos",
    "https://api.github.com/%zz",
    "https://api.github.com/\\evil",
    "",
    None,
    b"https://api.github.com/repos",
])
def test_exact_host_refuses_anything_but_plain_https_to_an_allowed_host(url):
    with pytest.raises(transport.ReleasePublicationError) as raised:
        exact_host(url)
    assert str(raised.value) == "refused url"


def canonical_member():
    return wheel._canonical_info("safe.py", (2020, 1, 1, 0, 0, 0))


def test_canonical_member_metadata_is_accepted():
    assert wheel._verify_member_metadata(canonical_member()) is None


@pytest.mark.parametrize("field,value,message", [
    ("external_attr", (0o100755) << 16, "wheel member mode is not canonical: safe.py"),
    ("external_attr", (0o120644) << 16, "wheel member mode is not canonical: safe.py"),
    ("create_system", 0, "wheel member host system is not canonical: safe.py"),
    ("create_version", 45, "wheel member ZIP version is not canonical: safe.py"),
    ("extract_version", 45, "wheel member ZIP version is not canonical: safe.py"),
    ("flag_bits", 0x800, "wheel member flags are not canonical: safe.py"),
    ("internal_attr", 1, "wheel member flags are not canonical: safe.py"),
    ("extra", b"\x55\x54", "wheel member carries extra metadata: safe.py"),
    ("comment", b"note", "wheel member carries extra metadata: safe.py"),
    ("compress_type", zipfile.ZIP_STORED, "wheel member compression is not canonical: safe.py"),
])
def test_member_metadata_refusals_name_the_weakened_property(field, value, message):
    info = canonical_member()
    setattr(info, field, value)

    with pytest.raises(wheel.CanonicalWheelError) as raised:
        wheel._verify_member_metadata(info)
    assert str(raised.value) == message


def test_member_metadata_reports_the_earliest_failed_check():
    info = canonical_member()
    info.compress_type = zipfile.ZIP_STORED
    info.comment = b"note"
    info.flag_bits = 1
    info.extract_version = 45
    info.create_system = 0
    info.external_attr = 0o100755 << 16
    expected = ["mode", "host system", "ZIP version", "flags", "extra metadata", "compression"]
    repairs = [
        ("external_attr", canonical_member().external_attr), ("create_system", 3),
        ("extract_version", canonical_member().extract_version), ("flag_bits", 0),
        ("comment", b""), ("compress_type", zipfile.ZIP_DEFLATED),
    ]

    for word, (field, value) in zip(expected, repairs, strict=True):
        with pytest.raises(wheel.CanonicalWheelError, match=word):
            wheel._verify_member_metadata(info)
        setattr(info, field, value)

    wheel._verify_member_metadata(info)
