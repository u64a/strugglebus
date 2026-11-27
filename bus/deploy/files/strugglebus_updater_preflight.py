"""Read-only checks for the first, deliberately narrow Debian updater profile.

No mount, credential content, candidate import or application lifecycle operation
is performed here. Tests inject filesystem/account observations, not CLI bypasses.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


WORKER = "strugglebus-updater"
WORKER_ID = 975
CACHE = Path("/var/lib/strugglebus-updater-cache")
CONFIG = Path("/etc/strugglebus-updater/worker.json")
MAX_FILESYSTEM = 1024 * 1024 * 1024
MAX_CONFIG = 8192
LIMITS = {
    "release_pages": 2, "releases_per_page": 20, "metadata_bytes": 2097152,
    "observation_ttl": 900, "request_timeout": 30, "request_attempts": 3,
    "retry_delay": 5, "check_timeout": 120, "prepare_timeout": 600,
    "candidate_bytes": 268435456, "artifact_bytes": 536870912,
    "journal_bytes": 4194304, "reserve_bytes": 268435456,
    "bytes_per_second": 4194304, "check_cooldown": 60,
    "receipt_count": 16, "connections": 4,
}


class BootstrapError(ValueError):
    """A static diagnostic, never credential contents or local identifiers."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapError(message)


def safe_path(value: str) -> Path:
    require(isinstance(value, str), "invalid absolute path")
    require(
        re.fullmatch(r"/[A-Za-z0-9_./-]{1,1023}", value) is not None
        and str(PurePosixPath(value)) == value
        and ".." not in PurePosixPath(value).parts,
        "invalid absolute path",
    )
    return Path(value)


def protected_directory(path: Path) -> None:
    metadata = path.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
        and metadata.st_mode & 0o022 == 0,
        "unprotected directory",
    )


def protected_cache_root(path: Path) -> None:
    metadata = path.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
        and metadata.st_gid == WORKER_ID
        and stat.S_IMODE(metadata.st_mode) == 0o710,
        "unsafe cache mount root",
    )


def protected_ancestors(path: Path) -> None:
    for parent in reversed(path.parents):
        protected_directory(parent)


def protected_file(path: Path, *, modes: set[int], maximum: int) -> os.stat_result:
    protected_ancestors(path)
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
        and metadata.st_nlink == 1 and 0 < metadata.st_size <= maximum
        and stat.S_IMODE(metadata.st_mode) in modes,
        "unprotected file",
    )
    return metadata


def read_protected(path: Path, maximum: int, modes: set[int]) -> bytes:
    before = protected_file(path, modes=modes, maximum=maximum)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(
            (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)
            == (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid)
            and opened.st_nlink == 1 and opened.st_size <= maximum,
            "file changed during inspection",
        )
        content = stream.read(maximum + 1)
    require(len(content) <= maximum, "file exceeds bound")
    return content


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "duplicate configuration key")
        result[key] = value
    return result


def reject_number(value: str) -> None:
    raise BootstrapError("invalid configuration number")


def validate_limits(value: object) -> dict[str, int]:
    require(isinstance(value, dict), "invalid limits")
    require(set(value) <= LIMITS.keys(), "unknown limit")
    result = dict(LIMITS)
    for key, limit in value.items():
        floor = key in {"reserve_bytes", "check_cooldown"}
        minimum = LIMITS[key] if floor else 1
        maximum = 1024 * 1024 * 1024 if floor else LIMITS[key]
        require(type(limit) is int and minimum <= limit <= maximum, "invalid limit")
        result[key] = limit
    require(result["artifact_bytes"] >= 2 * result["candidate_bytes"], "insufficient pair budget")
    return result


def validate_config(content: bytes, application_uid: int, data_dir: Path) -> dict[str, int]:
    require(len(content) <= MAX_CONFIG, "configuration exceeds bound")
    value = json.loads(
        content.decode("utf-8"), object_pairs_hook=unique_object,
        parse_constant=reject_number, parse_float=reject_number,
    )
    require(isinstance(value, dict) and set(value) == {
        "version", "application_uid", "application_data_dir", "cache_dir",
        "release_repository", "source_repository", "limits",
    }, "invalid configuration keys")
    require(type(value["version"]) is int and value["version"] == 2, "unknown configuration version")
    require(
        type(value["application_uid"]) is int and value["application_uid"] == application_uid,
        "application identity mismatch",
    )
    require(
        value["application_data_dir"] == str(data_dir)
        and value["cache_dir"] == str(CACHE / "state"),
        "configuration topology mismatch",
    )
    # The project's own repository, or the place releases came from up to 0.2.73. The updater
    # accepts a file naming either, so the file need not change at the moment of the move.
    require(
        (value["release_repository"], value["source_repository"]) in {
            ("u64a/strugglebus", "u64a/strugglebus"),
            ("NZCypher819/strugglebus-releases", "NZCypher819/strugglebus"),
        },
        "invalid repository identity",
    )
    return validate_limits(value["limits"])


def validate_accounts(user: str, group: str) -> tuple[int, int]:
    import grp
    import pwd

    application = pwd.getpwnam(user)
    application_group = grp.getgrnam(group)
    require(
        0 < application.pw_uid <= 2**31 - 1
        and application.pw_gid == application_group.gr_gid > 0
        and WORKER_ID not in {application.pw_uid, application.pw_gid}
        and user != WORKER and group != WORKER,
        "application account conflicts with worker",
    )
    validate_worker_users(pwd.getpwall())
    validate_worker_groups(grp.getgrall())
    return application.pw_uid, application_group.gr_gid


def validate_worker_users(accounts: list[object]) -> None:
    for account in accounts:
        if account.pw_name == WORKER or account.pw_uid == WORKER_ID:
            require(
                account.pw_name == WORKER and account.pw_uid == WORKER_ID
                and account.pw_gid == WORKER_ID and account.pw_shell == "/usr/sbin/nologin",
                "reserved worker identity is occupied",
            )
        elif account.pw_gid == WORKER_ID:
            raise BootstrapError("worker group is shared")
def validate_worker_groups(groups: list[object]) -> None:
    for entry in groups:
        if entry.gr_name == WORKER or entry.gr_gid == WORKER_ID:
            require(
                entry.gr_name == WORKER and entry.gr_gid == WORKER_ID and not entry.gr_mem,
                "reserved worker group is occupied",
            )
        require(WORKER not in entry.gr_mem, "worker has supplementary groups")


def mount_records(content: str) -> list[dict[str, str]]:
    require(len(content) <= 1024 * 1024, "mount topology exceeds bound")
    records = []
    for line in content.splitlines():
        left, separator, right = line.partition(" - ")
        fields, filesystem = left.split(), right.split()
        require(bool(separator) and len(fields) >= 6 and len(filesystem) == 3, "invalid mount topology")
        records.append(dict(
            device=fields[2], root=fields[3], target=fields[4],
            options=fields[5], kind=filesystem[0], source=filesystem[1],
        ))
    return records


def cache_mount(records: list[dict[str, str]], device: int) -> dict[str, str]:
    matches = [record for record in records if record["target"] == str(CACHE)]
    require(len(matches) == 1, "cache must be an exact dedicated mount")
    record = matches[0]
    require(
        record["kind"] == "ext4" and record["root"] == "/"
        and record["device"] == f"{os.major(device)}:{os.minor(device)}"
        and {"rw", "nodev", "nosuid", "noexec"} <= set(record["options"].split(",")),
        "unsupported cache filesystem",
    )
    require(
        sum(item["device"] == record["device"] for item in records) == 1
        and not any(item["target"].startswith(str(CACHE) + "/") for item in records),
        "cache has aliases or nested mounts",
    )
    return record


def persistent_mount(content: str, device: int) -> None:
    require(len(content) <= 65536, "fstab exceeds bound")
    entries = [
        line.split() for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    matches = [entry for entry in entries if len(entry) >= 2 and entry[1] == str(CACHE)]
    require(len(matches) == 1, "cache lacks unique persistent mount")
    entry = matches[0]
    validate_persistent_entry(entry)
    block = Path("/dev/disk/by-uuid") / entry[0].removeprefix("UUID=")
    metadata = block.stat()
    require(stat.S_ISBLK(metadata.st_mode) and metadata.st_rdev == device, "persistent device mismatch")


def validate_persistent_entry(entry: list[str]) -> None:
    require(
        len(entry) == 6 and entry[2] == "ext4" and entry[4:] == ["0", "2"],
        "unsupported persistent mount",
    )
    uuid = r"UUID=[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
    require(re.fullmatch(uuid, entry[0]) is not None, "persistent mount requires UUID")
    options = set(entry[3].split(","))
    require(
        {"rw", "nodev", "nosuid", "noexec"} <= options
        and options <= {
            "rw", "nodev", "nosuid", "noexec", "relatime", "noatime",
            "discard", "errors=remount-ro",
        },
        "unsafe persistent mount options",
    )


def validate_capacity(capacity: object, limits: dict[str, int], *, initialized: bool) -> dict[str, int]:
    total = capacity.f_blocks * capacity.f_frsize
    available = capacity.f_bavail * capacity.f_frsize
    required = limits["artifact_bytes"] + limits["journal_bytes"] + limits["reserve_bytes"]
    require(required <= total <= MAX_FILESYSTEM, "cache filesystem capacity outside bounds")
    minimum_free = limits["reserve_bytes"] if initialized else required
    require(available >= minimum_free, "insufficient cache free capacity")
    return {"capacity_bytes": total, "available_bytes": available}


def cache_layout() -> bool:
    protected_ancestors(CACHE)
    protected_cache_root(CACHE)
    names = set()
    for path in CACHE.iterdir():
        require(path.name in {"state", "lost+found"}, "cache filesystem contains unrelated data")
        names.add(path.name)
    if "lost+found" in names:
        path = CACHE / "lost+found"
        protected_directory(path)
        require(not any(path.iterdir()), "cache has unrecovered filesystem data")
    if "state" not in names:
        return False
    metadata = (CACHE / "state").lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == WORKER_ID
        and metadata.st_gid == WORKER_ID and stat.S_IMODE(metadata.st_mode) == 0o700,
        "unsafe existing worker storage",
    )
    return cache_admission(CACHE / "state")


def cache_admission(path: Path) -> bool:
    journal = path / "updater-journal.json"
    try:
        journal.lstat()
    except FileNotFoundError:
        require_pristine_cache(path)
        return False
    return True


def require_pristine_cache(path: Path) -> None:
    for entry in path.iterdir():
        require(entry.name == "updater-worker.lock", "missing history in non-pristine cache")
        info = entry.lstat()
        require(
            stat.S_ISREG(info.st_mode) and info.st_uid == WORKER_ID
            and info.st_gid == WORKER_ID and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1 and info.st_size == 0,
            "unsafe pristine cache lock",
        )


def container_manager() -> str | None:
    """Return the systemd container marker, or None on a VM or bare metal."""
    path = Path("/run/systemd/container")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    require(
        stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
        and metadata.st_mode & 0o022 == 0 and metadata.st_size <= 64,
        "unsafe container marker",
    )
    return path.read_text(encoding="ascii").strip()


def inspect_storage(data_dir: Path, limits: dict[str, int]) -> dict[str, int]:
    initialized = cache_layout()
    device = CACHE.stat().st_dev
    require(device != data_dir.stat().st_dev, "cache shares application filesystem")
    record = cache_mount(mount_records(Path("/proc/self/mountinfo").read_text()), device)
    if container_manager() == "lxc":
        # A Proxmox mount point is attached by the host from the container
        # config: the guest has neither its block node nor an fstab entry.
        require(safe_path(record["source"]).is_relative_to("/dev"), "cache source is not a block device")
    else:
        block = safe_path(record["source"]).stat()
        require(stat.S_ISBLK(block.st_mode) and block.st_rdev == device, "cache source is not its block device")
        persistent_mount(read_protected(Path("/etc/fstab"), 65536, {0o644, 0o640, 0o600}).decode(), device)
    sectors = Path(f"/sys/dev/block/{record['device']}/size").read_text().strip()
    require(sectors.isascii() and sectors.isdigit() and len(sectors) <= 16, "invalid block capacity")
    require(0 < int(sectors) * 512 <= MAX_FILESYSTEM, "block device exceeds cache ceiling")
    return validate_capacity(os.statvfs(CACHE), limits, initialized=initialized)


def inspect(config: Path, user: str, group: str, data_dir: Path) -> dict[str, int]:
    require(config == CONFIG, "unsupported configuration path")
    require(data_dir == Path("/var/lib/strugglebus"), "unsupported application topology")
    uid, gid = validate_accounts(user, group)
    metadata = protected_file(config, modes={0o600, 0o640}, maximum=MAX_CONFIG)
    require(metadata.st_gid in {0, WORKER_ID}, "unsafe configuration group")
    limits = validate_config(read_protected(config, MAX_CONFIG, {0o600, 0o640}), uid, data_dir)
    protected_ancestors(data_dir)
    data = data_dir.lstat()
    require(
        stat.S_ISDIR(data.st_mode) and data.st_uid == uid and data.st_gid == gid
        and stat.S_IMODE(data.st_mode) in {0o700, 0o750},
        "unsafe application directory",
    )
    require_no_data_acls(data_dir)
    inspect_runtime(gid)
    result = inspect_storage(data_dir, limits)
    return {"version": 1, "application_uid": uid, "application_gid": gid, **result}


def require_no_data_acls(path: Path) -> None:
    getter = getattr(os, "getxattr", None)
    absent = getattr(errno, "ENODATA", None)
    require(callable(getter) and type(absent) is int, "application ACL proof unavailable")
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            getter(path, name, follow_symlinks=False)
        except OSError as error:
            require(error.errno == absent, "application ACL proof unavailable")
        except NotImplementedError:
            raise BootstrapError("application ACL proof unavailable") from None
        else:
            raise BootstrapError("application ACLs are not permitted")


def inspect_runtime(application_gid: int) -> None:
    runtime = Path("/run/strugglebus-updater")
    if not runtime.exists() and not runtime.is_symlink():
        return
    protected_ancestors(runtime)
    info = runtime.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
        and stat.S_IMODE(info.st_mode) == 0o755,
        "unsafe socket parent",
    )
    socket_path = runtime / "worker.sock"
    if socket_path.exists() or socket_path.is_symlink():
        info = socket_path.lstat()
        require(
            stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
            and info.st_gid == application_gid and stat.S_IMODE(info.st_mode) == 0o660,
            "unsafe existing updater socket",
        )


def validate_code_entry(path: Path, root: Path) -> None:
    info = path.lstat()
    require(info.st_uid == 0, "installed code is not root-owned")
    if path == root / "venv/lib64" and stat.S_ISLNK(info.st_mode):
        require(os.readlink(path) == "lib", "unexpected interpreter library link")
        return
    require(info.st_mode & 0o022 == 0, "installed code is writable")
    if stat.S_ISDIR(info.st_mode):
        return
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "installed code has indirect files")


def verify_code(root: Path) -> dict[str, int]:
    require(
        root.parent == Path("/opt/strugglebus-updater/releases")
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", root.name) is not None,
        "unsupported worker release path",
    )
    protected_ancestors(root)
    protected_directory(root)
    count = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            count += 1
            require(count <= 100000, "installed code inventory exceeds bound")
            validate_code_entry(Path(directory) / name, root)
    for name in ("python", "python3", "python3.13"):
        info = (root / "venv/bin" / name).lstat()
        require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111), "missing copied interpreter")
    module = root / "venv/lib/python3.13/site-packages/strugglebus/update_worker.py"
    require(stat.S_ISREG(module.lstat().st_mode), "approved release lacks updater")
    return {"version": 1, "files_checked": count}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    host = modes.add_parser("host")
    host.add_argument("--config", required=True)
    host.add_argument("--application-user", required=True)
    host.add_argument("--application-group", required=True)
    host.add_argument("--application-data-dir", required=True)
    code = modes.add_parser("code")
    code.add_argument("--release-root", required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "code":
            result = verify_code(safe_path(args.release_root))
        else:
            result = inspect(
                safe_path(args.config), args.application_user,
                args.application_group, safe_path(args.application_data_dir),
            )
    except (BootstrapError, OSError, ValueError, KeyError, RecursionError):
        print('{"error":"updater-bootstrap-preflight-refused"}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
