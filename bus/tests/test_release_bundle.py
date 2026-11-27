from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import posixpath
import re
import sys
import tarfile

import pytest

from release_fixtures import run_git, source_repository, write_wheel


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "release_bundle",
    SCRIPTS / "release_bundle.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the release bundle module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ReleaseBundleError = MODULE.ReleaseBundleError
build_bundle = MODULE.build_bundle
validate_bundle = MODULE.validate_bundle

COMMIT = "1" * 40
TREE = "2" * 40
TAG = "v0.2.0"

SYSTEMD_CONTROLLER_TASKS = {
    "deploy/roles/systemd/tasks/main.yml",
    "deploy/roles/systemd/tasks/backup_timer.yml",
    "deploy/roles/release/tasks/maintenance_configuration.yml",
    "deploy/roles/guest_base/tasks/validated_python_helper.yml",
}


def _normal_task_imports(content: str) -> list[str]:
    declarations = re.findall(
        r"^[ \t]*(?:ansible\.builtin\.)?(?:include_tasks|import_tasks):",
        content, re.MULTILINE,
    )
    targets = re.findall(
        r"^[ \t]*(?:ansible\.builtin\.)?(?:include_tasks|import_tasks):"
        r"[ \t]*(?:\r?\n[ \t]+file:[ \t]*)?"
        r"([A-Za-z0-9_./-]+)[ \t]*\r?$",
        content, re.MULTILINE,
    )
    assert len(targets) == len(declarations), "ordinary task import must have an explicit static target"
    return targets


def _assert_normal_task_closure(
    archived: dict[str, str],
    controller: dict[str, str],
    roots: tuple[str, ...] = ("deploy/roles/systemd/tasks/main.yml",),
) -> set[str]:
    pending = list(roots)
    visited: set[str] = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        if name in archived:
            content = archived[name]
        else:
            assert name in SYSTEMD_CONTROLLER_TASKS, f"unbundled normal task import: {name}"
            content = controller[name]
        for imported in _normal_task_imports(content):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), imported))
            assert target.startswith("deploy/roles/"), f"unsafe normal task import: {target}"
            pending.append(target)
    return visited


def _write_wheel(path: Path) -> None:
    write_wheel(path, "0.2.0")


def _create_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str = "release",
) -> Path:
    dist = tmp_path / f"{name}-dist"
    dist.mkdir()
    _write_wheel(dist / "strugglebus-0.2.0-py3-none-any.whl")
    uv = tmp_path / f"{name}-uv"
    uv.write_bytes(b"pinned uv binary")
    output = tmp_path / name
    monkeypatch.setattr(
        MODULE,
        "resolve_release_identity",
        lambda *args, **kwargs: (COMMIT, TREE, 1_700_000_000, "0.2.0"),
    )
    build_bundle(REPOSITORY, dist, output, TAG, uv_binary=uv)
    return output


def _rewrite_manifest(directory: Path, update: object) -> None:
    manifest_path = directory / MODULE.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    assert callable(update)
    update(manifest)
    manifest_path.write_bytes(MODULE._canonical_json(manifest))
    paths = sorted(
        (
            directory / "strugglebus-0.2.0-py3-none-any.whl",
            directory / "requirements.lock",
            directory / "strugglebus-deployment-support-0.2.0.tar.gz",
            manifest_path,
        ),
        key=lambda path: path.name,
    )
    (directory / MODULE.CHECKSUMS_NAME).write_text(
        "".join(f"{MODULE._sha256(path)}  {path.name}\n" for path in paths),
        encoding="ascii",
    )


def test_release_bundle_is_deterministic_and_valid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = _create_bundle(monkeypatch, tmp_path, "first")
    second = _create_bundle(monkeypatch, tmp_path, "second")

    assert {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in first.iterdir()
    } == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in second.iterdir()
    }
    result = validate_bundle(
        first,
        expected_tag=TAG,
        expected_commit=COMMIT,
        expected_tree=TREE,
    )
    assert result["integrity"] == "sha256-verified"
    assert result["authenticity"] == "authenticated-github-acquisition-required"
    assert result["release_version"] == TAG


def test_bundle_missing_a_support_file_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    partial = tuple(
        item for item in MODULE.SUPPORT_FILES
        if item.archive != "helpers/strugglebus-inspector-contract.py"
    )
    monkeypatch.setattr(MODULE, "SUPPORT_FILES", partial)
    with pytest.raises(ReleaseBundleError, match="helper"):
        _create_bundle(monkeypatch, tmp_path)


def test_support_archive_is_exact_and_root_owned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = _create_bundle(monkeypatch, tmp_path)
    support_archive = bundle / "strugglebus-deployment-support-0.2.0.tar.gz"
    with tarfile.open(support_archive, mode="r:gz") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == [
            *sorted(item.archive for item in MODULE.SUPPORT_FILES),
            MODULE.SUPPORT_INDEX_NAME,
        ]
        assert not any(
            part in {"inventory", "tests", "protected"}
            for member in members
            for part in Path(member.name).parts
        )
        for member in members:
            assert member.isfile()
            assert not member.issym()
            assert not member.islnk()
            assert member.uid == 0
            assert member.gid == 0
            assert member.uname == "root"
            assert member.gname == "root"
            assert member.mtime == 1_700_000_000


def test_normal_systemd_task_imports_close_over_canonical_support_and_existing_controller(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _create_bundle(monkeypatch, tmp_path)
    archived: dict[str, str] = {}
    with tarfile.open(directory / "strugglebus-deployment-support-0.2.0.tar.gz", "r:gz") as archive:
        archive_names = set(archive.getnames())
        for name in archive_names:
            if not name.endswith(".yml"):
                continue
            stream = archive.extractfile(name)
            assert stream is not None
            archived[name] = stream.read().decode("utf-8")
    # These pre-existing controller files are deliberately not supplied by the
    # support archive; every added ordinary task dependency must be bundled.
    controller = {
        name: (REPOSITORY / name).read_text(encoding="utf-8")
        for name in SYSTEMD_CONTROLLER_TASKS
    }
    roots = (
        "deploy/roles/systemd/tasks/main.yml",
        "deploy/roles/release/tasks/maintenance_configuration.yml",
    )
    visited = _assert_normal_task_closure(archived, controller, roots)
    bundled_operator = "deploy/roles/systemd/tasks/operator_credential.yml"
    assert bundled_operator in visited
    assert "operator_credential.yml" in _normal_task_imports(controller[roots[0]])
    for admission in (
        archived[bundled_operator],
        controller["deploy/roles/release/tasks/maintenance_configuration.yml"],
    ):
        for setting in (
            "strugglebus_updater_socket_path",
            "updater_confirm_session_per_minute",
            "updater_confirm_global_per_minute",
            "updater_review_seconds",
            "updater_review_tickets",
        ):
            assert setting in admission
    assert "deploy/roles/systemd/tasks/updater_settings.yml" not in visited
    assert not (REPOSITORY / "deploy/roles/systemd/tasks/updater_settings.yml").exists()
    assert not any("updater_bootstrap" in name or "/roles/updater/" in name for name in archive_names)
    assert archive_names == {item.archive for item in MODULE.SUPPORT_FILES} | {MODULE.SUPPORT_INDEX_NAME}


def test_normal_task_closure_rejects_new_unbundled_import() -> None:
    main = "deploy/roles/systemd/tasks/main.yml"
    controller = {main: "---\n- name: New dependency\n  ansible.builtin.include_tasks: updater_settings.yml\n"}
    with pytest.raises(AssertionError, match="unbundled normal task import"):
        _assert_normal_task_closure({}, controller)


@pytest.mark.parametrize("imported", [
    'ansible.builtin.include_tasks: "{{ untrusted_task }}"\n',
    "ansible.builtin.import_tasks:\n  file: ../../../../outside.yml\n",
])
def test_normal_task_closure_refuses_dynamic_or_escaping_import(imported: str) -> None:
    controller = {"deploy/roles/systemd/tasks/main.yml": imported}
    with pytest.raises(AssertionError):
        _assert_normal_task_closure({}, controller)


def test_manifest_records_required_compatibility_without_private_data(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = _create_bundle(monkeypatch, tmp_path)
    content = (bundle / MODULE.MANIFEST_NAME).read_text(encoding="ascii")
    manifest = json.loads(content)

    assert manifest["compatibility"]["database"] == {
        "current_schema": 25,
        "downgrade_supported": False,
        "minimum_upgrade_schema": 1,
        "requires_verified_pre_migration_backup": True,
        "rollback_previous_schema": 24,
        "rollback_strategy": "restore-verified-backup-and-select-compatible-release",
    }
    assert manifest["protocol"] == {
        "capabilities": ["agent-access-freeze:global-v1"],
        "coordination_protocol_version": 1,
        "integration_guide_version": "1.19.0",
    }
    assert manifest["consumption"]["offline_publisher_authenticity"] is False
    assert manifest["consumption"]["offline_verification"] == "sha256-integrity-only"
    for forbidden in (
        "admin-token",
        "authorization",
        "bus.lan",
        "channel",
        "credential_bytes",
        "credential_secret",
        "inventory",
        "message",
    ):
        assert forbidden not in content.lower()


@pytest.mark.parametrize(
    "asset",
    [
        "strugglebus-0.2.0-py3-none-any.whl",
        "requirements.lock",
        "strugglebus-deployment-support-0.2.0.tar.gz",
        MODULE.MANIFEST_NAME,
        MODULE.CHECKSUMS_NAME,
    ],
)
def test_release_bundle_rejects_missing_or_tampered_assets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    asset: str,
) -> None:
    bundle = _create_bundle(monkeypatch, tmp_path)
    path = bundle / asset
    if asset == MODULE.CHECKSUMS_NAME:
        path.write_text("0" * 64 + "  requirements.lock\n", encoding="ascii")
    else:
        path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(ReleaseBundleError):
        validate_bundle(bundle)


def test_release_bundle_rejects_unexpected_asset(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = _create_bundle(monkeypatch, tmp_path)
    (bundle / "latest").write_text("mutable", encoding="ascii")
    with pytest.raises(ReleaseBundleError, match="unexpected"):
        validate_bundle(bundle)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (("release", "source_commit"), "3" * 40, "source commit"),
        (("release", "source_tree"), "4" * 40, "source tree"),
        (("release", "tag"), "v0.2.1", "tag and package"),
        (("compatibility", "database", "current_schema"), 26, "schema"),
        (("protocol", "coordination_protocol_version"), 2, "protocol"),
        (("protocol", "capabilities"), [], "capability"),
        (("manifest_version",), 2, "unsupported"),
    ],
)
def test_release_bundle_rejects_identity_and_compatibility_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    bundle = _create_bundle(monkeypatch, tmp_path)

    def update(manifest: dict[str, object]) -> None:
        target: object = manifest
        for part in field[:-1]:
            assert isinstance(target, dict)
            target = target[part]
        assert isinstance(target, dict)
        target[field[-1]] = value
        if field[0] == "release":
            release = manifest["release"]
            assert isinstance(release, dict)
            release["candidate_id"] = (
                f"{release['repository']}@{release['tag']}:"
                f"{release['source_commit']}:{release['source_tree']}"
            )

    _rewrite_manifest(bundle, update)
    with pytest.raises(ReleaseBundleError, match=message):
        validate_bundle(
            bundle,
            expected_commit=COMMIT,
            expected_tree=TREE,
        )


def test_release_bundle_rejects_package_downgrade(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = _create_bundle(monkeypatch, tmp_path)
    with pytest.raises(ReleaseBundleError, match="downgrade"):
        validate_bundle(bundle, minimum_package_version="0.3.0")


def test_release_identity_requires_annotated_clean_exact_tag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    responses = {
        ("cat-file", "-t", TAG): "tag",
        ("rev-parse", f"{TAG}^{{commit}}"): COMMIT,
        ("rev-parse", f"{COMMIT}^{{tree}}"): TREE,
        ("status", "--porcelain=v1", "--untracked-files=no"): "",
        ("diff", "--cached", "--name-only"): "",
        ("show", "-s", "--format=%ct", COMMIT): "1700000000",
    }
    monkeypatch.setattr(MODULE, "_package_version", lambda repository: "0.2.0")
    monkeypatch.setattr(
        MODULE,
        "_git",
        lambda repository, *arguments: responses[arguments],
    )

    assert MODULE.resolve_release_identity(
        tmp_path,
        TAG,
        expected_commit=COMMIT,
        expected_tree=TREE,
    ) == (COMMIT, TREE, 1_700_000_000, "0.2.0")

    responses[("cat-file", "-t", TAG)] = "commit"
    with pytest.raises(ReleaseBundleError, match="annotated"):
        MODULE.resolve_release_identity(tmp_path, TAG)


def test_release_manifest_rejects_duplicate_json_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = _create_bundle(monkeypatch, tmp_path)
    manifest = bundle / MODULE.MANIFEST_NAME
    content = manifest.read_text(encoding="ascii")
    manifest.write_text(
        content.replace('{"assets":', '{"manifest_version":1,"assets":', 1),
        encoding="ascii",
    )
    with pytest.raises(ReleaseBundleError, match="duplicate JSON key"):
        validate_bundle(bundle)


def _pre_tag_inputs(tmp_path: Path) -> tuple[Path, str, str, str, Path, Path]:
    root = tmp_path / "source"
    root.mkdir()
    commit, tree, version = source_repository(root)
    dist = tmp_path / "dist"
    dist.mkdir()
    write_wheel(dist / f"strugglebus-{version}-py3-none-any.whl", version)
    uv = tmp_path / "uv"
    uv.write_bytes(b"pinned uv binary")
    return root, commit, tree, version, dist, uv


def test_pre_tag_build_qualifies_exact_bytes_before_the_tag_exists(
    tmp_path: Path,
) -> None:
    root, commit, tree, version, dist, uv = _pre_tag_inputs(tmp_path)
    tag = f"v{version}"
    assert run_git(root, "tag", "--list") == ""

    manifest = build_bundle(
        root,
        dist,
        tmp_path / "release-assets",
        tag,
        expected_commit=commit,
        expected_tree=tree,
        uv_binary=uv,
        pre_tag=True,
    )

    assert manifest["release"]["source_commit"] == commit
    assert manifest["release"]["source_tree"] == tree
    assert manifest["release"]["tag"] == tag
    assert manifest["package"]["version"] == version
    assert len(manifest["consumption"]["release_assets"]) == 5
    validated = validate_bundle(
        tmp_path / "release-assets",
        expected_tag=tag,
        expected_commit=commit,
        expected_tree=tree,
    )
    assert validated["source_commit"] == commit
    assert run_git(root, "tag", "--list") == ""


def test_a_build_in_the_projects_repository_says_so_and_only_validates_as_such(tmp_path: Path) -> None:
    root, commit, tree, version, dist, uv = _pre_tag_inputs(tmp_path)
    tag = f"v{version}"

    manifest = build_bundle(
        root, dist, tmp_path / "release-assets", tag, expected_commit=commit, expected_tree=tree,
        uv_binary=uv, pre_tag=True, source_repository="u64a/strugglebus",
    )

    assert manifest["release"]["repository"] == "u64a/strugglebus"
    assert manifest["release"]["candidate_id"] == f"u64a/strugglebus@{tag}:{commit}:{tree}"
    validate_bundle(tmp_path / "release-assets", expected_repository="u64a/strugglebus")
    # A bus that expects the former repository, 0.2.72 or older, does not take it.
    with pytest.raises(ReleaseBundleError):
        validate_bundle(tmp_path / "release-assets")


def test_a_build_cannot_claim_some_other_repository(tmp_path: Path) -> None:
    root, commit, tree, version, dist, uv = _pre_tag_inputs(tmp_path)

    with pytest.raises(ReleaseBundleError, match="not one a bus accepts"):
        build_bundle(
            root, dist, tmp_path / "release-assets", f"v{version}", expected_commit=commit,
            expected_tree=tree, uv_binary=uv, pre_tag=True, source_repository="someone/else",
        )

    assert not (tmp_path / "release-assets").exists()


def test_default_build_requires_an_existing_annotated_tag(tmp_path: Path) -> None:
    root, commit, tree, version, dist, uv = _pre_tag_inputs(tmp_path)
    tag = f"v{version}"

    with pytest.raises(ReleaseBundleError, match="git command failed: cat-file"):
        build_bundle(
            root,
            dist,
            tmp_path / "missing-tag",
            tag,
            expected_commit=commit,
            expected_tree=tree,
            uv_binary=uv,
        )

    run_git(root, "tag", "--no-sign", tag, commit)
    with pytest.raises(ReleaseBundleError, match="existing annotated tag"):
        build_bundle(
            root,
            dist,
            tmp_path / "lightweight-tag",
            tag,
            expected_commit=commit,
            expected_tree=tree,
            uv_binary=uv,
        )

    run_git(root, "tag", "--delete", tag)
    run_git(root, "tag", "--annotate", "--no-sign", "--message", tag, tag, commit)
    manifest = build_bundle(
        root,
        dist,
        tmp_path / "annotated-tag",
        tag,
        expected_commit=commit,
        expected_tree=tree,
        uv_binary=uv,
    )

    assert manifest["release"]["source_commit"] == commit
    assert manifest["release"]["tag"] == tag


def test_pre_tag_mode_requires_and_compares_exact_expected_identities(
    tmp_path: Path,
) -> None:
    root, commit, tree, version, dist, uv = _pre_tag_inputs(tmp_path)
    tag = f"v{version}"

    with pytest.raises(ReleaseBundleError, match="expected commit and tree"):
        MODULE.resolve_release_identity(root, tag, pre_tag=True)
    with pytest.raises(ReleaseBundleError, match="expected commit and tree"):
        MODULE.resolve_release_identity(
            root, tag, expected_commit=commit, pre_tag=True
        )
    with pytest.raises(ReleaseBundleError, match="exact 40-character identities"):
        MODULE.resolve_release_identity(
            root,
            tag,
            expected_commit="HEAD",
            expected_tree=tree,
            pre_tag=True,
        )
    with pytest.raises(ReleaseBundleError, match="wrong tree"):
        MODULE.resolve_release_identity(
            root,
            tag,
            expected_commit=commit,
            expected_tree="9" * 40,
            pre_tag=True,
        )
    with pytest.raises(ReleaseBundleError, match="git command failed: rev-parse"):
        MODULE.resolve_release_identity(
            root,
            tag,
            expected_commit="9" * 40,
            expected_tree=tree,
            pre_tag=True,
        )

    resolved = MODULE.resolve_release_identity(
        root,
        tag,
        expected_commit=commit,
        expected_tree=tree,
        pre_tag=True,
    )
    assert resolved[0] == commit
    assert resolved[1] == tree
    assert resolved[2] == int(run_git(root, "show", "-s", "--format=%ct", commit))
    assert resolved[3] == version

    with pytest.raises(ReleaseBundleError, match="release tag must be v"):
        MODULE.resolve_release_identity(
            root,
            "release-1",
            expected_commit=commit,
            expected_tree=tree,
            pre_tag=True,
        )
    with pytest.raises(ReleaseBundleError, match="version does not match"):
        MODULE.resolve_release_identity(
            root,
            "v9.9.9",
            expected_commit=commit,
            expected_tree=tree,
            pre_tag=True,
        )


def test_pre_tag_mode_still_refuses_dirty_tracked_state(tmp_path: Path) -> None:
    root, commit, tree, version, dist, uv = _pre_tag_inputs(tmp_path)
    lock = root / "requirements.lock"
    lock.write_text(lock.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ReleaseBundleError, match="tracked dirty state"):
        build_bundle(
            root,
            dist,
            tmp_path / "dirty",
            f"v{version}",
            expected_commit=commit,
            expected_tree=tree,
            uv_binary=uv,
            pre_tag=True,
        )
