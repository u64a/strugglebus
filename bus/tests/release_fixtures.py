"""Shared release fixtures: realistic wheels and qualification documents."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_script(name: str) -> Any:
    """Import one release script module by path exactly once per session."""

    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _record_hash(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
    return f"sha256={encoded.rstrip(b'=').decode('ascii')}"


def wheel_members(version: str) -> dict[str, bytes]:
    """Return the exact uncompressed members of the fixture wheel."""

    dist_info = f"strugglebus-{version}.dist-info"
    members: dict[str, bytes] = {
        "strugglebus/__init__.py": (
            '"""Strugglebus package."""\n\n__version__ = "%s"\n' % version
        ).encode("utf-8"),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: strugglebus\n"
            f"Version: {version}\n"
            "Requires-Python: <3.14,>=3.13\n"
            "\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: strugglebus-tests\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode("utf-8"),
        f"{dist_info}/entry_points.txt": (
            "[console_scripts]\nstrugglebus = strugglebus.cli:main\n"
        ).encode("utf-8"),
    }
    record_name = f"{dist_info}/RECORD"
    rows = [
        f"{name},{_record_hash(payload)},{len(payload)}"
        for name, payload in sorted(members.items())
    ]
    rows.append(f"{record_name},,")
    members[record_name] = ("\n".join(rows) + "\n").encode("utf-8")
    return members


def write_wheel(
    path: Path,
    version: str = "0.2.0",
    *,
    mode: int = 0o644,
    date_time: tuple[int, int, int, int, int, int] = (2020, 1, 1, 0, 0, 0),
    members: dict[str, bytes] | None = None,
) -> None:
    """Write a builder-shaped wheel whose ZIP metadata is intentionally varied."""

    payloads = wheel_members(version) if members is None else members
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in payloads.items():
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, payload)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def run_git(root: Path, *arguments: str) -> str:
    """Run one real git command inside a temporary fixture repository."""

    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout.strip()


def source_repository(root: Path) -> tuple[str, str, str]:
    """Create a real temporary git repository holding the release sources."""

    bundle = load_script("release_bundle")
    tracked = ["src/strugglebus/__init__.py", "requirements.lock"]
    tracked.extend(support.source for support in bundle.SUPPORT_FILES)
    for relative in tracked:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY / relative, destination)
    run_git(root, "init")
    run_git(root, "config", "user.email", "release-tests@example.invalid")
    run_git(root, "config", "user.name", "Release Tests")
    run_git(root, "config", "commit.gpgsign", "false")
    run_git(root, "add", "--all")
    run_git(root, "commit", "--message", "release qualification source")
    commit = run_git(root, "rev-parse", "HEAD")
    tree = run_git(root, "rev-parse", "HEAD^{tree}")
    return commit, tree, bundle._package_version(root)


def build_pre_tag_bundle(tmp_path: Path) -> tuple[Path, str, str, str]:
    """Build the exact five assets from a real, untagged temporary repository."""

    bundle = load_script("release_bundle")
    root = tmp_path / "source"
    root.mkdir()
    commit, tree, version = source_repository(root)
    dist = tmp_path / "dist"
    dist.mkdir()
    write_wheel(dist / f"strugglebus-{version}-py3-none-any.whl", version)
    uv = tmp_path / "uv"
    uv.write_bytes(b"pinned uv binary")
    output = tmp_path / "release-assets"
    bundle.build_bundle(
        root,
        dist,
        output,
        f"v{version}",
        expected_commit=commit,
        expected_tree=tree,
        uv_binary=uv,
        pre_tag=True,
    )
    return output, commit, tree, version


OWNER = "NZCypher819"
QUALIFICATION_RUN_ID = 4242
QUALIFICATION_RUN_ATTEMPT = 1
ARTIFACT_ID = 9001
ARTIFACT_DIGEST = "a" * 64
ARTIFACT_SIZE = 4096
SOURCE_DATE_EPOCH = 1_700_000_000
ISSUED_AT = 1_700_000_100
PUBLISHED_AT = 1_700_000_200


def _artifact_record(
    *,
    artifact_id: int,
    name: str,
    size: int,
    digest: str,
    run_id: int,
    commit: str,
) -> dict[str, Any]:
    return {
        "digest": digest,
        "expired": False,
        "id": artifact_id,
        "name": name,
        "size_in_bytes": size,
        "workflow_run": {
            "head_branch": "main",
            "head_sha": commit,
            "id": run_id,
        },
    }


def qualification_responses(
    *,
    repository: str,
    tag: str,
    commit: str,
    run_id: int = QUALIFICATION_RUN_ID,
    run_attempt: int = QUALIFICATION_RUN_ATTEMPT,
    artifact_id: int = ARTIFACT_ID,
    artifact_digest: str = ARTIFACT_DIGEST,
    artifact_size: int = ARTIFACT_SIZE,
) -> dict[str, dict[str, Any]]:
    """Return the read-only API responses the publisher uses to resolve one run."""

    qualification = load_script("release_qualification")
    runs_path = (
        f"repos/{repository}/actions/workflows/"
        f"{qualification.QUALIFICATION_WORKFLOW}/runs?"
        f"event=workflow_dispatch&head_sha={commit}&status=completed&per_page=100"
    )
    artifacts_path = (
        f"repos/{repository}/actions/runs/{run_id}/artifacts?page=1&per_page=100"
    )
    return {
        runs_path: {
            "workflow_runs": [
                {
                    "actor": {"login": OWNER},
                    "conclusion": "success",
                    "event": "workflow_dispatch",
                    "head_branch": "main",
                    "head_sha": commit,
                    "id": run_id,
                    "run_attempt": run_attempt,
                    "status": "completed",
                    "triggering_actor": {"login": OWNER},
                }
            ]
        },
        artifacts_path: {
            "artifacts": [
                _artifact_record(
                    artifact_id=artifact_id,
                    name=qualification.asset_artifact_name(tag, run_id),
                    size=artifact_size,
                    digest=artifact_digest,
                    run_id=run_id,
                    commit=commit,
                )
            ]
        },
    }


def write_qualification_receipt(
    directory: Path,
    destination: Path,
    *,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
    version: str,
    run_id: int = QUALIFICATION_RUN_ID,
    run_attempt: int = QUALIFICATION_RUN_ATTEMPT,
    artifact_id: int = ARTIFACT_ID,
    artifact_digest: str = ARTIFACT_DIGEST,
    artifact_size: int = ARTIFACT_SIZE,
    issued_at: int = ISSUED_AT,
    validity_seconds: int | None = None,
    now: int = PUBLISHED_AT,
) -> Any:
    """Write the real canonical receipt and return its publication binding."""

    qualification = load_script("release_qualification")
    bundle = load_script("release_bundle")
    manifest = json.loads(
        (directory / bundle.MANIFEST_NAME).read_text(encoding="ascii")
    )
    destination.mkdir(parents=True, exist_ok=True)
    receipt = qualification.build_receipt(
        directory,
        repository=repository,
        tag=tag,
        commit=commit,
        tree=tree,
        version=version,
        run_id=run_id,
        run_attempt=run_attempt,
        actor=OWNER,
        workflow_sha=commit,
        approved_by=OWNER,
        approval=qualification.APPROVAL_PHRASE,
        uv_binary_sha256=manifest["build"]["uv"]["binary_sha256"],
        helper_sha256=qualification.helper_digest(REPOSITORY),
        source_date_epoch=SOURCE_DATE_EPOCH,
        issued_at=issued_at,
        **(
            {}
            if validity_seconds is None
            else {"validity_seconds": validity_seconds}
        ),
    )
    receipt_path = destination / qualification.RECEIPT_NAME
    receipt_path.write_bytes(canonical_json(receipt))
    return qualification.QualificationBinding(
        receipt_path=receipt_path,
        run_id=run_id,
        artifact_id=artifact_id,
        artifact_name=qualification.asset_artifact_name(tag, run_id),
        artifact_digest=artifact_digest,
        artifact_size_bytes=artifact_size,
        helper_sha256=qualification.helper_digest(REPOSITORY),
        now=now,
    )
