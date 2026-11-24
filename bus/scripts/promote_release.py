"""Operator-approved, build-once release promotion; never a deployment controller."""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.parse
import uuid
import zipfile

from promotion_common import PromotionError
from promotion_state import ReceiptStore
from promotion_transport import PromotionAPI, deadline
from publish_immutable_release import (
    ReleasePublicationError,
    inspect_release_identity,
    verify_published_release,
)
from release_bundle import (
    DISQUALIFIED_PRODUCTION_VERSIONS,
    MAX_ASSET_BYTES,
    ReleaseBundleError,
)
from release_qualification import (
    APPROVAL_PHRASE,
    MAX_ARTIFACT_BYTES,
    MAX_RECEIPT_BYTES,
    QUALIFICATION_WORKFLOW,
    RECEIPT_NAME,
    ArtifactIdentity,
    QualificationBinding,
    QualificationError,
    asset_artifact_name,
    expected_asset_names,
    resolve_qualification,
    validate_qualification_trigger,
    verify_qualified_release,
)
from validate_release_trigger import (
    REPOSITORY,
    SHA_PATTERN,
    TAG_PATTERN,
    TriggerValidationError,
    validate_release_trigger,
)


OWNER = "NZCypher819"
ROOT = f"repos/{REPOSITORY}"
PHASES = (
    "created",
    "dispatch_intent",
    "qualifying",
    "qualified",
    "tag_object_intent",
    "tag_object_ready",
    "tag_ref_intent",
    "publishing",
    "complete",
)
HEX256 = re.compile(r"^[0-9a-f]{64}$")
MAX_SOURCE_BYTES = 64 * 1024
HANDOFF = "docs/DEPLOYMENT.md#maintenance-window-upgrade"
CONSUMED_TAGS = frozenset({"v0.2.0", "v0.2.1", "v0.2.2", "v0.2.3"})


def _keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PromotionError(f"{label} has invalid fields")
    return value


def _integer(value: Any, maximum: int = 2**53 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise PromotionError("identity contains an invalid integer")
    return value


def _pattern(value: Any, pattern: re.Pattern[str], maximum: int = 64) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or pattern.fullmatch(value) is None
    ):
        raise PromotionError("identity contains an invalid string")
    return value


def _identity(tag: str, commit: str) -> None:
    _pattern(tag, TAG_PATTERN)
    _pattern(commit, SHA_PATTERN)
    if tag in CONSUMED_TAGS or tag[1:] in DISQUALIFIED_PRODUCTION_VERSIONS:
        raise PromotionError("this release version is permanently disqualified")


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))


def _tag_payload(operation: dict[str, Any]) -> dict[str, Any]:
    qualification = operation["qualification"]
    annotation = {
        "operation_id": operation["operation_id"],
        "repository": REPOSITORY,
        "run_id": qualification["run_id"],
        "artifact_id": qualification["artifact_id"],
        "artifact_digest": qualification["artifact_digest"],
        "receipt_sha256": qualification["receipt_sha256"],
    }
    return {
        "tag": operation["tag"],
        "object": operation["commit"],
        "type": "commit",
        "message": "Strugglebus promotion v1\n" + _canonical(annotation) + "\n",
        "tagger": {
            "name": OWNER,
            "email": f"{OWNER}@users.noreply.github.com",
            "date": datetime.fromtimestamp(
                operation["created_at"], timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }


def tag_object_sha(payload: dict[str, Any]) -> str:
    """Hash our fixed UTC Git object, not a GitHub-normalized existing tag."""

    tagger = payload["tagger"]
    epoch = int(datetime.strptime(
        tagger["date"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc).timestamp())
    content = (
        f"object {payload['object']}\ntype commit\ntag {payload['tag']}\n"
        f"tagger {tagger['name']} <{tagger['email']}> {epoch} +0000\n\n"
        f"{payload['message']}"
    ).encode("ascii")
    return hashlib.sha1(
        f"tag {len(content)}\0".encode("ascii") + content,
        usedforsecurity=False,
    ).hexdigest()


def validate_operation(value: Any) -> dict[str, Any]:
    operation = _keys(value, {
        "receipt_version", "operation_id", "repository", "owner", "tag", "commit",
        "tree", "created_at", "ci_run_id", "phase", "dispatch", "qualification",
        "tag_intent", "release",
    }, "promotion receipt")
    if (
        type(operation["receipt_version"]) is not int
        or operation["receipt_version"] != 1
        or operation["repository"] != REPOSITORY
        or operation["owner"] != OWNER
        or operation["phase"] not in PHASES
    ):
        raise PromotionError("promotion receipt identity or version is invalid")
    _pattern(operation["operation_id"], re.compile(r"^[0-9a-f]{32}$"), 32)
    _identity(operation["tag"], operation["commit"])
    _pattern(operation["tree"], SHA_PATTERN)
    _integer(operation["created_at"], 4102444799)
    _integer(operation["ci_run_id"])
    phase = PHASES.index(operation["phase"])
    dispatch = operation["dispatch"]
    if dispatch is not None:
        _keys(dispatch, {"acknowledged", "baseline_ids"}, "dispatch intent")
        ids = dispatch["baseline_ids"]
        if (
            type(dispatch["acknowledged"]) is not bool
            or not isinstance(ids, list) or len(ids) > 100
        ):
            raise PromotionError("dispatch intent is invalid")
        for run_id in ids:
            _integer(run_id)
        if ids != sorted(set(ids)):
            raise PromotionError("dispatch baseline is invalid")
    if phase == 0 and dispatch is not None:
        raise PromotionError("created receipt already has a dispatch intent")
    if phase == 1 and (dispatch is None or dispatch["acknowledged"]):
        raise PromotionError("unknown dispatch intent is inconsistent")
    qualification = operation["qualification"]
    if (qualification is not None) != (phase >= 3):
        raise PromotionError("qualification phase is inconsistent")
    if qualification is not None:
        _keys(qualification, {
            "run_id", "run_attempt", "artifact_id", "artifact_name",
            "artifact_size_bytes", "artifact_digest", "receipt_sha256",
            "expires_at", "helper_sha256", "assets",
        }, "qualified binding")
        for key in ("run_id", "artifact_id"):
            _integer(qualification[key])
        _integer(qualification["run_attempt"], 1000)
        _integer(qualification["artifact_size_bytes"], MAX_ARTIFACT_BYTES)
        _integer(qualification["expires_at"], 4102444799)
        for key in ("artifact_digest", "receipt_sha256", "helper_sha256"):
            _pattern(qualification[key], HEX256)
        if qualification["artifact_name"] != asset_artifact_name(
            operation["tag"], qualification["run_id"]
        ):
            raise PromotionError("qualification artifact name is inconsistent")
        assets = qualification["assets"]
        if not isinstance(assets, list) or len(assets) != 5:
            raise PromotionError("qualification asset set is invalid")
        for asset in assets:
            _keys(asset, {"name", "size_bytes", "sha256"}, "qualified asset")
            _integer(asset["size_bytes"], MAX_ASSET_BYTES)
            _pattern(asset["sha256"], HEX256)
        if [asset["name"] for asset in assets] != expected_asset_names(
            operation["tag"][1:]
        ):
            raise PromotionError("qualification asset names are invalid")
        if sum(asset["size_bytes"] for asset in assets) > MAX_ARTIFACT_BYTES:
            raise PromotionError("qualified asset aggregate exceeds its limit")
    intent = operation["tag_intent"]
    if (intent is not None) != (phase >= 4):
        raise PromotionError("tag phase is inconsistent")
    if intent is not None:
        _keys(intent, {"payload", "expected_sha"}, "tag intent")
        if (
            intent["payload"] != _tag_payload(operation)
            or intent["expected_sha"] != tag_object_sha(intent["payload"])
        ):
            raise PromotionError("tag intent does not match its provenance")
    release = operation["release"]
    if (release is not None) != (phase == 8):
        raise PromotionError("release phase is inconsistent")
    if release is not None:
        _keys(release, {"id", "verified_at"}, "completed release")
        _integer(release["id"])
        _integer(release["verified_at"], 4102444799)
        if release["verified_at"] >= qualification["expires_at"]:
            raise PromotionError("completion was not verified before qualification expiry")
    return operation


def _source(api: Any, path: str, commit: str) -> bytes:
    record = api.get(f"{ROOT}/contents/{path}?ref={commit}")
    if (
        not isinstance(record, dict) or record.get("type") != "file"
        or record.get("encoding") != "base64"
        or record.get("path") != path
        or type(record.get("size")) is not int
        or not 0 < record["size"] <= MAX_SOURCE_BYTES
        or not isinstance(record.get("content"), str)
        or len(record["content"]) > 2 * MAX_SOURCE_BYTES
    ):
        raise PromotionError("exact source file response is invalid")
    try:
        content = base64.b64decode(
            "".join(record["content"].splitlines()), validate=True
        )
    except (ValueError, binascii.Error):
        raise PromotionError("exact source file encoding is invalid") from None
    if len(content) != record["size"]:
        raise PromotionError("exact source file size is invalid")
    return content


def preflight(api: Any, tag: str, commit: str) -> dict[str, Any]:
    _identity(tag, commit)
    user = api.get("user")
    if not isinstance(user, dict) or user.get("login") != OWNER:
        raise PromotionError("authenticated GitHub identity is not the owner", code=4)
    gate = validate_qualification_trigger(
        api, repository=REPOSITORY, tag=tag, commit=commit, actor=OWNER,
        workflow_sha=commit, event_name="workflow_dispatch",
        ref="refs/heads/main", approved_by=OWNER, approval=APPROVAL_PHRASE,
    )
    settings = api.get(f"{ROOT}/immutable-releases")
    if not isinstance(settings, dict) or settings.get("enabled") is not True:
        raise PromotionError("immutable releases must already be enabled")
    source = _source(api, "src/strugglebus/__init__.py", commit)
    try:
        module = ast.parse(source)
    except (SyntaxError, ValueError):
        raise PromotionError("exact source package version cannot be parsed") from None
    versions = [
        node.value.value
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets)
        and isinstance(node.value, ast.Constant)
    ]
    if versions != [tag[1:]]:
        raise PromotionError("tag does not match the exact main package version")
    commit_record = api.get(f"{ROOT}/git/commits/{commit}")
    if (
        not isinstance(commit_record, dict) or commit_record.get("sha") != commit
        or not isinstance(commit_record.get("tree"), dict)
    ):
        raise PromotionError("exact commit response is invalid")
    return {
        "tree": _pattern(commit_record["tree"].get("sha"), SHA_PATTERN),
        "ci_run_id": gate["ci_run_id"],
        "helper_sha256": hashlib.sha256(
            _source(api, "scripts/canonical_wheel.py", commit)
        ).hexdigest(),
    }


def _tag_ref(api: Any, tag: str) -> Any:
    return api.optional_get(
        f"{ROOT}/git/ref/tags/{urllib.parse.quote(tag, safe='')}"
    )


def _require_absent(api: Any, tag: str) -> None:
    if _tag_ref(api, tag) is not None or api.find_release(REPOSITORY, tag) is not None:
        raise PromotionError(
            "tag or release is already consumed; use its intact receipt, never retag"
        )


def _runs(api: Any, commit: str, *, publication_tag: str | None = None) -> list[Any]:
    workflow = "release.yml" if publication_tag is not None else QUALIFICATION_WORKFLOW
    event = "create" if publication_tag is not None else "workflow_dispatch"
    response = api.get(
        f"{ROOT}/actions/workflows/{workflow}/runs?"
        f"event={event}&head_sha={commit}&per_page=100"
    )
    records = response.get("workflow_runs") if isinstance(response, dict) else None
    if not isinstance(records, list) or len(records) >= 100:
        raise PromotionError("workflow listing completeness cannot be established")
    if response.get("total_count", len(records)) != len(records):
        raise PromotionError("workflow listing is truncated")
    selected = []
    for run in records:
        if not isinstance(run, dict):
            raise PromotionError("workflow run is invalid")
        actor = run.get("actor")
        triggering = run.get("triggering_actor")
        if (
            run.get("event") != event or run.get("head_sha") != commit
            or run.get("head_branch") != (publication_tag or "main")
            or not isinstance(actor, dict) or actor.get("login") != OWNER
            or not isinstance(triggering, dict) or triggering.get("login") != OWNER
        ):
            continue
        _integer(run.get("id"))
        _integer(run.get("run_attempt"), 1000)
        if run.get("status") not in {
            "queued", "in_progress", "completed", "waiting", "pending", "requested"
        }:
            raise PromotionError("workflow run status is invalid")
        selected.append(run)
    if len({run["id"] for run in selected}) != len(selected):
        raise PromotionError("workflow listing contains duplicate run identities")
    return selected


def _qualification(api: Any, tag: str, commit: str) -> tuple[str, Any, list[Any]]:
    runs = _runs(api, commit)
    active = [run for run in runs if run["status"] != "completed"]
    successful = [run for run in runs if run.get("conclusion") == "success"
                  and run["status"] == "completed"]
    if len(active) > 1 or (active and successful):
        raise PromotionError("multiple unattributed qualification runs need reconciliation")
    if active:
        return "pending", None, runs
    if successful:
        return "ready", resolve_qualification(
            api, repository=REPOSITORY, tag=tag, commit=commit
        ), runs
    if runs:
        raise PromotionError("previous qualification failed; no automatic replacement dispatch")
    return "absent", None, runs


def plan(api: Any, tag: str, commit: str) -> dict[str, Any]:
    gate = preflight(api, tag, commit)
    _require_absent(api, tag)
    state, resolved, _ = _qualification(api, tag, commit)
    return {
        "repository": REPOSITORY, "owner": OWNER, "tag": tag, "commit": commit,
        "tree": gate["tree"], "ci_run_id": gate["ci_run_id"], "read_only": True,
        "qualification": state,
        "run_id": resolved["run_id"] if resolved else None,
        "next_action": {
            "absent": "explicitly approve one qualification dispatch",
            "pending": "observe the unattributed same-commit run; do not dispatch",
            "ready": "explicitly approve exact artifact verification and tagging",
        }[state],
    }


def extract_qualification(archive_path: Path, destination: Path, version: str) -> None:
    """Bound central-directory parsing before ZipFile allocates member objects."""

    size = archive_path.stat().st_size
    if not 22 <= size <= MAX_ARTIFACT_BYTES:
        raise PromotionError("qualification ZIP size is invalid")
    with archive_path.open("rb") as stream:
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
        offset = tail.rfind(b"PK\x05\x06")
        end_offset = size - len(tail) + offset
        if offset >= 0 and end_offset >= 20:
            # ZipFile lets this locator override the ordinary footer below.
            # It can sit outside tail when the archive has a maximum-size comment.
            stream.seek(end_offset - 20)
            if stream.read(4) == b"PK\x06\x07":
                raise PromotionError("ZIP64 qualification archives are unsupported")
    if offset < 0 or len(tail) - offset < 22:
        raise PromotionError("qualification ZIP footer is invalid")
    _, disk, central_disk, disk_count, count, central_size, central_offset, comment = (
        struct.unpack("<4s4H2LH", tail[offset:offset + 22])
    )
    if (
        disk != 0 or central_disk != 0 or disk_count != count
        or not 6 <= count <= 8 or central_size > 16 * 1024
        or central_offset + central_size != size - len(tail) + offset
        or offset + 22 + comment != len(tail)
    ):
        raise PromotionError("qualification ZIP directory is unsupported or oversized")
    limits = {f"release-assets/{name}": MAX_ASSET_BYTES
              for name in expected_asset_names(version)}
    limits[f"qualification/{RECEIPT_NAME}"] = MAX_RECEIPT_BYTES
    directories = {"release-assets/", "qualification/"}
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if (
                any(member.orig_filename != member.filename for member in members)
                or len(names) != len(set(names))
                or set(names) - (set(limits) | directories)
            ):
                raise PromotionError("qualification ZIP member set is invalid")
            if set(names) & set(limits) != set(limits):
                raise PromotionError("qualification ZIP lacks required files")
            if sum(member.file_size for member in members) > MAX_ARTIFACT_BYTES:
                raise PromotionError("qualification ZIP expansion exceeds its limit")
            for member in members:
                mode = member.external_attr >> 16
                if member.flag_bits & 1 or member.compress_type not in {
                    zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED
                }:
                    raise PromotionError("qualification ZIP encoding is unsupported")
                if member.filename in directories:
                    if (
                        not member.is_dir() or member.file_size != 0
                        or stat.S_IFMT(mode) not in {0, stat.S_IFDIR}
                    ):
                        raise PromotionError("qualification ZIP directory is invalid")
                elif (
                    not 0 < member.file_size <= limits[member.filename]
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                ):
                    raise PromotionError("qualification ZIP file is unsafe or oversized")
            destination.mkdir(mode=0o700)
            for folder in ("release-assets", "qualification"):
                (destination / folder).mkdir(mode=0o700)
            for member in members:
                if member.filename in directories:
                    continue
                target = destination / member.filename
                with archive.open(member) as source, target.open("xb") as output:
                    os.chmod(target, 0o600)
                    written = 0
                    while chunk := source.read(min(1024 * 1024, member.file_size - written + 1)):
                        written += len(chunk)
                        if written > member.file_size:
                            raise PromotionError("qualification ZIP payload exceeds its size")
                        output.write(chunk)
                    if written != member.file_size:
                        raise PromotionError("qualification ZIP payload is incomplete")
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as error:
        if isinstance(error, PromotionError):
            raise
        raise PromotionError("qualification ZIP could not be verified") from None


def _save(store: ReceiptStore, operation: dict[str, Any], *, create: bool = False) -> None:
    validate_operation(operation)
    store.write(operation, create=create)


def _validate_tag_object(record: Any, operation: dict[str, Any]) -> None:
    intent = operation["tag_intent"]
    payload = intent["payload"]
    if (
        not isinstance(record, dict) or record.get("sha") != intent["expected_sha"]
        or record.get("tag") != operation["tag"]
        or record.get("message") != payload["message"]
        or not isinstance(record.get("object"), dict)
        or record["object"].get("type") != "commit"
        or record["object"].get("sha") != operation["commit"]
        or record.get("tagger") != payload["tagger"]
    ):
        raise PromotionError("annotated tag object conflicts with the recorded operation")


def _own_ref(api: Any, operation: dict[str, Any]) -> bool:
    ref = _tag_ref(api, operation["tag"])
    if ref is None:
        return False
    expected = operation["tag_intent"]["expected_sha"]
    if (
        not isinstance(ref, dict) or ref.get("ref") != f"refs/tags/{operation['tag']}"
        or not isinstance(ref.get("object"), dict)
        or ref["object"].get("type") != "tag" or ref["object"].get("sha") != expected
    ):
        raise PromotionError("existing tag does not belong to this operation; never retag")
    _validate_tag_object(api.get(f"{ROOT}/git/tags/{expected}"), operation)
    return True


def _release_observation(api: Any, operation: dict[str, Any]) -> Any:
    qualified = operation["qualification"]
    if qualified is None:
        if api.find_release(REPOSITORY, operation["tag"]) is not None:
            raise PromotionError("unexpected release before qualification was recorded")
        return None
    observed = inspect_release_identity(
        api, repository=REPOSITORY, tag=operation["tag"], commit=operation["commit"],
        assets=qualified["assets"],
    )
    if operation["release"] is not None and (
        observed is None or observed["state"] != "immutable"
        or observed["release"]["id"] != operation["release"]["id"]
    ):
        raise PromotionError("previously verified immutable release identity changed")
    return observed


def status(api: Any, operation: dict[str, Any]) -> dict[str, Any]:
    validate_operation(operation)
    user = api.get("user")
    if not isinstance(user, dict) or user.get("login") != OWNER:
        raise PromotionError("authenticated GitHub identity is not the owner", code=4)
    tag_present = False
    if operation["tag_intent"] is not None:
        tag_present = _own_ref(api, operation)
    elif _tag_ref(api, operation["tag"]) is not None:
        raise PromotionError("unrecorded tag is already consumed")
    observed = _release_observation(api, operation)
    if observed is not None and not tag_present:
        raise PromotionError("release exists without this operation's annotated tag")
    result = {
        "repository": REPOSITORY, "tag": operation["tag"],
        "commit": operation["commit"], "tree": operation["tree"],
        "recorded_phase": operation["phase"], "read_only": True,
        "tag_present": tag_present,
        "release_state": observed["state"] if observed else "absent",
        "verification": "metadata-only; no new byte or qualification verification",
        "next_action": "resume this receipt with explicit approval; never redispatch unknown intent",
    }
    if operation["release"] is not None:
        result.update(
            prior_verification_at=operation["release"]["verified_at"],
            release_url=f"https://github.com/{REPOSITORY}/releases/tag/{operation['tag']}",
            next_action=HANDOFF,
        )
    if operation["qualification"] is None:
        runs = _runs(api, operation["commit"])
        result["observed_run_ids"] = [run["id"] for run in runs]
        dispatch = operation["dispatch"]
        if dispatch is None:
            result["dispatch_outcome"] = "no dispatch intent recorded"
        elif not runs:
            result["dispatch_outcome"] = (
                "dispatch accepted; no run visible yet"
                if dispatch["acknowledged"]
                else "no event visible; outcome remains unknown"
            )
        else:
            result["dispatch_outcome"] = "run inputs require artifact verification"
    return result


def promote(
    api: Any,
    store: ReceiptStore,
    *,
    tag: str,
    commit: str,
    approval: str,
    resume: bool = False,
    poll_seconds: float = 10,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    _identity(tag, commit)
    if approval != APPROVAL_PHRASE:
        raise PromotionError("exact owner approval phrase is required", code=2)
    with store.locked():
        if resume:
            operation = validate_operation(store.read())
            if (operation["tag"], operation["commit"]) != (tag, commit):
                raise PromotionError("resume identity does not match the receipt")
            if operation["phase"] == "complete":
                return status(api, operation)
        else:
            gate = preflight(api, tag, commit)
            _require_absent(api, tag)
            operation = {
                "receipt_version": 1, "operation_id": uuid.uuid4().hex,
                "repository": REPOSITORY, "owner": OWNER, "tag": tag, "commit": commit,
                "tree": gate["tree"], "created_at": int(now()),
                "ci_run_id": gate["ci_run_id"], "phase": "created", "dispatch": None,
                "qualification": None, "tag_intent": None, "release": None,
            }
            _save(store, operation, create=True)
        observe_only = (
            PHASES.index(operation["phase"]) >= PHASES.index("tag_ref_intent")
            and _own_ref(api, operation)
        )
        if observe_only:
            user = api.get("user")
            if not isinstance(user, dict) or user.get("login") != OWNER:
                raise PromotionError("authenticated GitHub identity is not the owner", code=4)
            gate = {
                "tree": operation["tree"],
                "helper_sha256": hashlib.sha256(
                    _source(api, "scripts/canonical_wheel.py", commit)
                ).hexdigest(),
            }
            if operation["phase"] == "tag_ref_intent":
                operation["phase"] = "publishing"
                _save(store, operation)
        else:
            gate = preflight(api, tag, commit)
        if gate["tree"] != operation["tree"]:
            raise PromotionError("source tree no longer matches the recorded identity")
        if operation["qualification"] is None:
            _require_absent(api, tag)
            while True:
                state, resolved, runs = _qualification(api, tag, commit)
                if state == "ready":
                    break
                if state == "absent" and operation["phase"] == "created":
                    operation["dispatch"] = {
                        "acknowledged": False, "baseline_ids": sorted(run["id"] for run in runs)
                    }
                    operation["phase"] = "dispatch_intent"
                    _save(store, operation)
                    preflight(api, tag, commit)
                    _require_absent(api, tag)
                    api.dispatch(tag, commit)
                    operation["dispatch"]["acknowledged"] = True
                    operation["phase"] = "qualifying"
                    _save(store, operation)
                elif state == "pending" and operation["phase"] == "created":
                    operation["phase"] = "qualifying"
                    _save(store, operation)
                sleep(poll_seconds)
                preflight(api, tag, commit)
        else:
            if int(now()) >= operation["qualification"]["expires_at"]:
                raise PromotionError("qualification expired; use read-only status, not a new dispatch")
            resolved = resolve_qualification(api, repository=REPOSITORY, tag=tag, commit=commit)
        artifact: ArtifactIdentity = resolved["artifact"]
        with tempfile.TemporaryDirectory(prefix=".promotion-", dir=store.path.parent) as temporary:
            workspace = Path(temporary)
            archive = workspace / "qualified.zip"
            api.download_artifact(artifact, archive)
            extracted = workspace / "qualified"
            extract_qualification(archive, extracted, tag[1:])
            archive.unlink()
            receipt_path = extracted / "qualification" / RECEIPT_NAME
            assets_directory = extracted / "release-assets"
            binding = QualificationBinding(
                receipt_path=receipt_path, run_id=resolved["run_id"],
                artifact_id=artifact.id, artifact_name=artifact.name,
                artifact_digest=artifact.digest, artifact_size_bytes=artifact.size_bytes,
                helper_sha256=gate["helper_sha256"], now=int(now()),
            )
            verified = verify_qualified_release(
                api, assets_directory, binding,
                repository=REPOSITORY, tag=tag, commit=commit, tree=operation["tree"],
            )
            receipt = json.loads(receipt_path.read_bytes())
            qualified = {
                "run_id": resolved["run_id"], "run_attempt": resolved["run_attempt"],
                "artifact_id": artifact.id, "artifact_name": artifact.name,
                "artifact_size_bytes": artifact.size_bytes, "artifact_digest": artifact.digest,
                "receipt_sha256": verified["receipt_sha256"],
                "expires_at": verified["expires_at"], "helper_sha256": gate["helper_sha256"],
                "assets": receipt["assets"],
            }
            if operation["qualification"] is None:
                operation["qualification"] = qualified
                operation["phase"] = "qualified"
                _save(store, operation)
            elif operation["qualification"] != qualified:
                raise PromotionError("qualification drifted from the protected receipt")

            def mutation_gate() -> None:
                fresh = preflight(api, tag, commit)
                if fresh["tree"] != operation["tree"] or fresh["helper_sha256"] != qualified["helper_sha256"]:
                    raise PromotionError("trusted source identity drifted")
                verify_qualified_release(
                    api, assets_directory, replace(binding, now=int(now())),
                    repository=REPOSITORY, tag=tag, commit=commit, tree=operation["tree"],
                )

            if operation["phase"] == "qualified":
                mutation_gate()
                _require_absent(api, tag)
                payload = _tag_payload(operation)
                operation["tag_intent"] = {
                    "payload": payload, "expected_sha": tag_object_sha(payload)
                }
                operation["phase"] = "tag_object_intent"
                _save(store, operation)
                mutation_gate()
                _require_absent(api, tag)
                record = api.create_tag(payload)
                _validate_tag_object(record, operation)
                operation["phase"] = "tag_object_ready"
                _save(store, operation)
            if operation["phase"] == "tag_object_intent":
                expected = operation["tag_intent"]["expected_sha"]
                while True:
                    mutation_gate()
                    record = api.optional_get(f"{ROOT}/git/tags/{expected}")
                    if record is not None:
                        _validate_tag_object(record, operation)
                        operation["phase"] = "tag_object_ready"
                        _save(store, operation)
                        break
                    sleep(poll_seconds)
            if operation["phase"] == "tag_object_ready":
                mutation_gate()
                _require_absent(api, tag)
                _validate_tag_object(
                    api.get(f"{ROOT}/git/tags/{operation['tag_intent']['expected_sha']}"),
                    operation,
                )
                operation["phase"] = "tag_ref_intent"
                _save(store, operation)
                mutation_gate()
                _require_absent(api, tag)
                api.create_ref(tag, operation["tag_intent"]["expected_sha"])
            if operation["phase"] == "tag_ref_intent":
                while not _own_ref(api, operation):
                    mutation_gate()
                    sleep(poll_seconds)
                validate_release_trigger(
                    api, repository=REPOSITORY, tag=tag, event_sha=commit,
                    event_ref=f"refs/tags/{tag}", ref_type="tag", actor=OWNER,
                    workflow_sha=commit,
                )
                operation["phase"] = "publishing"
                _save(store, operation)
            while True:
                if not _own_ref(api, operation):
                    raise PromotionError("recorded tag disappeared; never recreate it")
                observed = _release_observation(api, operation)
                publisher_runs = _runs(api, commit, publication_tag=tag)
                if len(publisher_runs) > 1:
                    raise PromotionError("multiple publisher runs require operator reconciliation")
                if observed is not None and observed["state"] == "immutable" and publisher_runs:
                    release = verify_published_release(
                        api, assets_directory, repository=REPOSITORY,
                        tag=tag, commit=commit, tree=operation["tree"],
                    )
                    verify_qualified_release(
                        api, assets_directory, replace(binding, now=int(now())),
                        repository=REPOSITORY, tag=tag, commit=commit, tree=operation["tree"],
                    )
                    operation["release"] = {"id": release["id"], "verified_at": int(now())}
                    operation["phase"] = "complete"
                    _save(store, operation)
                    return {
                        "phase": "complete", "repository": REPOSITORY, "tag": tag,
                        "commit": commit, "tree": operation["tree"], "release_id": release["id"],
                        "release_url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}",
                        "qualification_run_id": qualified["run_id"],
                        "qualification_artifact_id": artifact.id,
                        "qualification_artifact_digest": artifact.digest,
                        "verification": "exact qualified and immutable published bytes",
                        "next_action": HANDOFF, "deployment_performed": False,
                    }
                if publisher_runs and publisher_runs[0]["status"] == "completed":
                    raise PromotionError(
                        "publisher completed without a verified immutable release; "
                        "tag is consumed, no automatic rerun or repair"
                    )
                if int(now()) >= qualified["expires_at"]:
                    raise PromotionError("qualification expired while observing publication")
                sleep(poll_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "status", "promote"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--gh", default="gh", help="trusted gh or WSL gh.exe executable")
        subparser.add_argument("--timeout-seconds", type=int, default=2700)
        if command != "status":
            subparser.add_argument("--tag", required=True)
            subparser.add_argument("--commit", required=True)
        if command != "plan":
            subparser.add_argument("--receipt", type=Path, required=True)
        if command == "promote":
            subparser.add_argument("--approval", required=True)
            subparser.add_argument("--resume", action="store_true")
            subparser.add_argument("--poll-seconds", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        if os.name != "posix" or not sys.platform.startswith("linux"):
            raise PromotionError("promotion requires Linux or WSL; native Windows is unsupported", code=3)
        if not 60 <= args.timeout_seconds <= 3600:
            raise PromotionError("deadline must be between 60 and 3600 seconds", code=2)
        if args.command == "promote" and not 2 <= args.poll_seconds <= 60:
            raise PromotionError("poll interval must be between 2 and 60 seconds", code=2)
        if args.command == "promote" and args.approval != APPROVAL_PHRASE:
            raise PromotionError("exact owner approval phrase is required", code=2)
        if args.command != "status":
            _identity(args.tag, args.commit)
        with deadline(args.timeout_seconds):
            api = PromotionAPI.from_gh(args.gh)
            if args.command == "plan":
                result = plan(api, args.tag, args.commit)
            elif args.command == "status":
                result = status(api, ReceiptStore(args.receipt).read())
            else:
                result = promote(
                    api, ReceiptStore(args.receipt), tag=args.tag, commit=args.commit,
                    approval=args.approval, resume=args.resume, poll_seconds=args.poll_seconds,
                )
        print(_canonical(result))
        return 0
    except PromotionError as error:
        print(_canonical({"error": str(error)}), file=sys.stderr)
        return error.code
    except (QualificationError, TriggerValidationError, ReleaseBundleError, ReleasePublicationError):
        print('{"error":"release trust validation failed; inspect read-only state"}', file=sys.stderr)
        return 6
    except OSError:
        print('{"error":"operator storage or transport is unavailable"}', file=sys.stderr)
        return 6
    except KeyboardInterrupt:
        print('{"error":"interrupted; resume the same receipt without repeating unknown mutations"}',
              file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
