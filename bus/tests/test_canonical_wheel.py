from __future__ import annotations

import base64
import hashlib
import shutil
import stat
import subprocess  # nosec B404
import sys
import zipfile
from pathlib import Path

import pytest

from release_fixtures import REPOSITORY, load_script, wheel_members, write_wheel


MODULE = load_script("canonical_wheel")
CanonicalWheelError = MODULE.CanonicalWheelError

VERSION = "0.2.26"
WHEEL_NAME = f"strugglebus-{VERSION}-py3-none-any.whl"
EPOCH = 1_700_000_000


def _members(path: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(path) as archive:
        return archive.infolist()


def _payloads(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _write_raw(path: Path, members: dict[str, bytes], **kwargs: object) -> None:
    write_wheel(path, VERSION, members=members, **kwargs)  # type: ignore[arg-type]


def test_different_timestamps_and_modes_produce_identical_canonical_bytes(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.whl"
    second = tmp_path / "second.whl"
    write_wheel(first, VERSION, mode=0o644, date_time=(2020, 1, 1, 0, 0, 0))
    write_wheel(second, VERSION, mode=0o660, date_time=(2031, 7, 9, 13, 45, 30))

    assert first.read_bytes() != second.read_bytes()

    canonical_first = tmp_path / "canonical-first.whl"
    canonical_second = tmp_path / "canonical-second.whl"
    MODULE.normalize_wheel(first, canonical_first, timestamp=EPOCH)
    MODULE.normalize_wheel(second, canonical_second, timestamp=EPOCH)

    assert canonical_first.read_bytes() == canonical_second.read_bytes()
    assert (
        hashlib.sha256(canonical_first.read_bytes()).hexdigest()
        == hashlib.sha256(canonical_second.read_bytes()).hexdigest()
    )


def test_canonical_wheel_fixes_timestamps_modes_and_zip_metadata(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.whl"
    write_wheel(source, VERSION, mode=0o660, date_time=(2024, 5, 6, 7, 8, 9))
    canonical = tmp_path / WHEEL_NAME
    result = MODULE.normalize_wheel(source, canonical, timestamp=EPOCH + 1)

    assert result["source_date_epoch"] == EPOCH
    for info in _members(canonical):
        assert info.date_time == MODULE.canonical_date_time(EPOCH)
        assert info.date_time[5] % 2 == 0
        assert info.external_attr >> 16 == stat.S_IFREG | 0o644
        assert info.create_system == 3
        assert info.create_version == 20
        assert info.extract_version == 20
        assert info.flag_bits == 0
        assert info.internal_attr == 0
        assert info.extra == b""
        assert info.comment == b""


def test_canonical_wheel_preserves_order_names_and_exact_payloads(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.whl"
    write_wheel(source, VERSION, mode=0o600, date_time=(1999, 12, 31, 23, 59, 58))
    canonical = tmp_path / WHEEL_NAME
    result = MODULE.normalize_wheel(source, canonical, timestamp=EPOCH)

    assert [info.filename for info in _members(canonical)] == [
        info.filename for info in _members(source)
    ]
    assert _payloads(canonical) == _payloads(source)
    assert result["members"] == list(wheel_members(VERSION))
    assert result["record"] == f"strugglebus-{VERSION}.dist-info/RECORD"


def test_verify_rejects_a_wheel_that_is_not_canonical(tmp_path: Path) -> None:
    source = tmp_path / "source.whl"
    write_wheel(source, VERSION, mode=0o660, date_time=(2024, 5, 6, 7, 8, 8))

    with pytest.raises(CanonicalWheelError, match="mode is not canonical"):
        MODULE.verify_canonical_wheel(source)

    canonical = tmp_path / WHEEL_NAME
    MODULE.normalize_wheel(source, canonical, timestamp=EPOCH)
    MODULE.verify_canonical_wheel(canonical, timestamp=EPOCH)
    with pytest.raises(CanonicalWheelError, match="accepted build timestamp"):
        MODULE.verify_canonical_wheel(canonical, timestamp=EPOCH + 86_400)


@pytest.mark.parametrize(
    ("timestamp", "message"),
    [
        (315532799, "safe ZIP range"),
        (4102444800, "safe ZIP range"),
        (True, "must be an integer"),
    ],
)
def test_canonical_timestamps_outside_the_zip_range_are_rejected(
    tmp_path: Path,
    timestamp: object,
    message: str,
) -> None:
    source = tmp_path / "source.whl"
    write_wheel(source, VERSION)
    with pytest.raises(CanonicalWheelError, match=message):
        MODULE.normalize_wheel(source, tmp_path / WHEEL_NAME, timestamp=timestamp)
    assert not (tmp_path / WHEEL_NAME).exists()


def test_record_integrity_is_validated_before_normalization(tmp_path: Path) -> None:
    members = wheel_members(VERSION)
    record_name = f"strugglebus-{VERSION}.dist-info/RECORD"
    metadata_name = f"strugglebus-{VERSION}.dist-info/METADATA"
    members[metadata_name] = members[metadata_name] + b"X-Injected: yes\n"
    source = tmp_path / "source.whl"
    _write_raw(source, members)

    with pytest.raises(CanonicalWheelError, match="RECORD hash mismatch"):
        MODULE.normalize_wheel(source, tmp_path / WHEEL_NAME, timestamp=EPOCH)
    assert record_name in members
    assert not (tmp_path / WHEEL_NAME).exists()


def test_record_size_and_self_hash_rules_are_enforced(tmp_path: Path) -> None:
    dist_info = f"strugglebus-{VERSION}.dist-info"
    record_name = f"{dist_info}/RECORD"
    members = wheel_members(VERSION)
    text = members[record_name].decode("utf-8")
    members[record_name] = text.replace(f"{record_name},,", f"{record_name},,0").encode()
    resized = tmp_path / "resized.whl"
    _write_raw(resized, members)
    with pytest.raises(CanonicalWheelError, match="must not hash itself"):
        MODULE.verify_canonical_wheel(resized)

    members = wheel_members(VERSION)
    text = members[record_name].decode("utf-8")
    payload = members[f"{dist_info}/METADATA"]
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
    digest = f"sha256={encoded.rstrip(b'=').decode('ascii')}"
    members[record_name] = text.replace(
        f"{dist_info}/METADATA,{digest},{len(payload)}",
        f"{dist_info}/METADATA,{digest},{len(payload) + 1}",
    ).encode()
    wrong_size = tmp_path / "wrong-size.whl"
    _write_raw(wrong_size, members)
    with pytest.raises(CanonicalWheelError, match="RECORD size mismatch"):
        MODULE.verify_canonical_wheel(wrong_size)


def test_unlisted_and_missing_record_members_are_rejected(tmp_path: Path) -> None:
    members = wheel_members(VERSION)
    members["strugglebus/extra.py"] = b"print('extra')\n"
    unlisted = tmp_path / "unlisted.whl"
    _write_raw(unlisted, members)
    with pytest.raises(CanonicalWheelError, match="does not list every wheel member"):
        MODULE.verify_canonical_wheel(unlisted)

    members = wheel_members(VERSION)
    del members[f"strugglebus-{VERSION}.dist-info/RECORD"]
    without_record = tmp_path / "without-record.whl"
    _write_raw(without_record, members)
    with pytest.raises(CanonicalWheelError, match="exactly one dist-info RECORD"):
        MODULE.verify_canonical_wheel(without_record)


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("../escape.py", "traverses"),
        ("nested/../../escape.py", "traverses"),
        ("/absolute.py", "traverses"),
        ("./relative.py", "unsafe"),
        ("strugglebus/caf\u00e9.py", "not ASCII"),
    ],
)
def test_traversal_and_unsafe_member_names_are_rejected(
    tmp_path: Path,
    name: str,
    message: str,
) -> None:
    source = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(source, mode="w") as archive:
        info = zipfile.ZipInfo("placeholder")
        info.filename = name
        archive.writestr(info, b"payload")

    with pytest.raises(CanonicalWheelError, match=message):
        MODULE.verify_canonical_wheel(source)


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("windows\\escape.py", "unsafe"),
        ("strugglebus/", "directory entry"),
        ("", "bounded string"),
        ("x" * 256, "bounded string"),
    ],
)
def test_member_name_policy_rejects_unsafe_shapes(name: str, message: str) -> None:
    with pytest.raises(CanonicalWheelError, match=message):
        MODULE._require_safe_name(name)


def test_duplicate_member_names_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.whl"
    with zipfile.ZipFile(source, mode="w") as archive:
        archive.writestr("strugglebus/__init__.py", b"first")
        archive.writestr("strugglebus/__init__.py", b"second")

    with pytest.raises(CanonicalWheelError, match="duplicate member"):
        MODULE.verify_canonical_wheel(source)


def test_symlink_directory_and_special_entries_are_rejected(tmp_path: Path) -> None:
    symlinked = tmp_path / "symlink.whl"
    with zipfile.ZipFile(symlinked, mode="w") as archive:
        info = zipfile.ZipInfo("strugglebus/link.py")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, b"../../etc/passwd")
    with pytest.raises(CanonicalWheelError, match="not a regular file"):
        MODULE.verify_canonical_wheel(symlinked)

    setuid = tmp_path / "setuid.whl"
    with zipfile.ZipFile(setuid, mode="w") as archive:
        info = zipfile.ZipInfo("strugglebus/tool.py")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | stat.S_ISUID | 0o755) << 16
        archive.writestr(info, b"payload")
    with pytest.raises(CanonicalWheelError, match="special mode"):
        MODULE.verify_canonical_wheel(setuid)

    directories = tmp_path / "directory.whl"
    with zipfile.ZipFile(directories, mode="w") as archive:
        archive.writestr("strugglebus/", b"")
    with pytest.raises(CanonicalWheelError, match="directory entry"):
        MODULE.verify_canonical_wheel(directories)


def test_normalize_refuses_to_clobber_an_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "source.whl"
    write_wheel(source, VERSION)
    destination = tmp_path / WHEEL_NAME
    destination.write_bytes(b"existing")

    with pytest.raises(CanonicalWheelError, match="already exists"):
        MODULE.normalize_wheel(source, destination, timestamp=EPOCH)
    assert destination.read_bytes() == b"existing"


def test_cli_normalizes_and_verifies_with_source_date_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "source.whl"
    write_wheel(source, VERSION, mode=0o600, date_time=(2022, 3, 4, 5, 6, 7))
    destination = tmp_path / WHEEL_NAME
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(EPOCH))
    monkeypatch.setattr(
        sys,
        "argv",
        ["canonical_wheel.py", "normalize", str(source), str(destination)],
    )

    assert MODULE.main() == 0
    normalized = capsys.readouterr().out

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "canonical_wheel.py",
            "verify",
            str(destination),
            "--source-date-epoch",
            str(EPOCH),
        ],
    )
    assert MODULE.main() == 0
    assert capsys.readouterr().out == normalized

    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    with pytest.raises(CanonicalWheelError, match="SOURCE_DATE_EPOCH is required"):
        MODULE.resolve_source_date_epoch(None)


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is unavailable")
def test_freshly_built_wheel_normalizes_deterministically(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copyfile(REPOSITORY / name, source_root / name)
    shutil.copytree(REPOSITORY / "src", source_root / "src",
                    ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    build_root = tmp_path / "fresh-build"
    build_root.mkdir()
    result = subprocess.run(  # nosec B603
        (
            shutil.which("uv") or "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(build_root),
        ),
        cwd=source_root,
        capture_output=True,
        check=False,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        pytest.skip(f"uv build is unavailable in this environment: {result.stderr[-200:]}")
    wheels = sorted(build_root.glob("*.whl"))
    assert len(wheels) == 1

    first = tmp_path / "first-canonical.whl"
    second = tmp_path / "second-canonical.whl"
    MODULE.normalize_wheel(wheels[0], first, timestamp=EPOCH)
    MODULE.normalize_wheel(wheels[0], second, timestamp=EPOCH + 1)

    assert first.read_bytes() == second.read_bytes()
    assert _payloads(first) == _payloads(wheels[0])
    verified = MODULE.verify_canonical_wheel(first, timestamp=EPOCH)
    assert verified["source_date_epoch"] == EPOCH
    assert verified["members"] == [info.filename for info in _members(wheels[0])]
