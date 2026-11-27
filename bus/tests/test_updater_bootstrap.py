from __future__ import annotations

from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import runpy
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from strugglebus.update_types import UpdateLimits


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/files/strugglebus_updater_preflight.py"
SPEC = importlib.util.spec_from_file_location("updater_preflight", SOURCE)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
ERROR = M.BootstrapError
MIB = 1024 * 1024


def metadata(**changes):
    values = dict(
        st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_size=32,
        st_nlink=1, st_dev=2051, st_ino=1, st_rdev=2051,
    )
    return SimpleNamespace(**(values | changes))


def config(**changes):
    return {
        "version": 2, "application_uid": 900,
        "application_data_dir": str(Path("/var/lib/strugglebus")),
        "cache_dir": str(M.CACHE / "state"),
        "release_repository": "NZCypher819/strugglebus-releases",
        "source_repository": "NZCypher819/strugglebus",
        "limits": {},
    } | changes


def parse(value):
    return M.validate_config(
        json.dumps(value).encode(), 900, Path("/var/lib/strugglebus"),
    )


@pytest.fixture
def device_numbers(monkeypatch):
    monkeypatch.setattr(M.os, "major", lambda value: value // 256, raising=False)
    monkeypatch.setattr(M.os, "minor", lambda value: value % 256, raising=False)


def mount_line(**changes):
    values = dict(
        device="8:3", root="/", target=str(M.CACHE), options="rw,nodev,nosuid,noexec",
        kind="ext4", source="/dev/mapper/cache",
    ) | changes
    return (
        f"30 20 {values['device']} {values['root']} {values['target']} "
        f"{values['options']} - {values['kind']} {values['source']} rw\n"
    )


def fstab(**changes):
    values = dict(
        source="UUID=00000000-0000-0000-0000-000000000001", target=str(M.CACHE),
        kind="ext4", options="rw,nodev,nosuid,noexec",
    ) | changes
    return "{source} {target} {kind} {options} 0 2\n".format(**values)


def test_static_deployment_contract():
    contract = runpy.run_path(str(ROOT / "deploy/tests/updater_bootstrap_unit.py"))
    assert contract["main"]() == 0
    with pytest.raises(AssertionError):
        contract["require_markers"]("safe", ("missing",))
    with pytest.raises(AssertionError, match="explicit validation"):
        contract["require"](False, "explicit validation")


def test_bootstrap_contract_guards_survive_optimized_python():
    program = """
import runpy
import sys
contract = runpy.run_path(sys.argv[1])
service = contract["read"]("roles/updater/templates/strugglebus-updater.service.j2")
socket = contract["read"]("roles/updater/templates/strugglebus-updater.socket.j2")
try:
    contract["validate_units"](service + "\\nSystemCallFilter=~@kill\\n", socket)
except AssertionError:
    raise SystemExit(0)
raise SystemExit("optimized validation accepted forbidden syscall policy")
"""
    result = subprocess.run(
        [
            sys.executable, "-I", "-B", "-O", "-c", program,
            str(ROOT / "deploy/tests/updater_bootstrap_unit.py"),
        ],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_normal_controller_setting_admission_uses_bundled_operator_task():
    contract = runpy.run_path(str(ROOT / "deploy/tests/contract.py"))
    systemd = (ROOT / "deploy/roles/systemd/tasks/main.yml").read_text()
    operator = (ROOT / "deploy/roles/systemd/tasks/operator_credential.yml").read_text()
    maintenance = (ROOT / "deploy/roles/release/tasks/maintenance_configuration.yml").read_text()
    assert not (ROOT / "deploy/roles/systemd/tasks/updater_settings.yml").exists()
    assert "updater_settings.yml" not in systemd + operator + maintenance
    assert "ansible.builtin.include_tasks: operator_credential.yml" in systemd
    assert (
        operator.index("Require an updater socket")
        < operator.index("Validate the optional guest-side operator credential reference")
    )
    for name in (
        "Require an updater socket outside application writable directories",
        "Validate explicitly configured updater application ceilings",
    ):
        first = contract["task_body"](operator, name).strip()
        second = contract["task_body"](maintenance, name).strip()
        assert first == second
        assert "ansible.builtin.assert:" in first


@pytest.mark.parametrize("old,new", [
    ("'status' if updater_journal.stat.exists else 'init'", "'init' if updater_journal.stat.exists else 'status'"),
    ('- "{{ updater_history_action }}"', "- init"),
    ("updater_journal.stat.mode | default('') == '0600'", "true"),
    ("updater_existing_units.results | selectattr('stat.exists') | list | length == 0", "true"),
    ("timeout: 30", "timeout: 30\n  failed_when: false"),
])
def test_bootstrap_history_contract_refuses_reinitialization_or_ignored_failures(old, new):
    contract = runpy.run_path(str(ROOT / "deploy/tests/updater_bootstrap_unit.py"))
    tasks = (ROOT / "deploy/roles/updater/tasks/main.yml").read_text()
    with pytest.raises(AssertionError):
        contract["validate_history"](tasks.replace(old, new))


def test_limits_match_worker_and_narrow_only():
    assert M.LIMITS == asdict(UpdateLimits())
    assert parse(config()) == M.LIMITS
    assert parse(config(limits={"candidate_bytes": MIB, "artifact_bytes": 2 * MIB}))["candidate_bytes"] == MIB


def test_safety_floors_allow_only_bounded_upward_tightening():
    exact = {"reserve_bytes": 256 * MIB, "check_cooldown": 60}
    assert parse(config(limits=exact)) == M.LIMITS
    stricter = parse(config(limits={"reserve_bytes": 300 * MIB, "check_cooldown": 120}))
    assert stricter == asdict(UpdateLimits(reserve_bytes=300 * MIB, check_cooldown=120))
    M.validate_capacity(capacity(), stricter, initialized=False)
    with pytest.raises(ERROR, match="free capacity"):
        M.validate_capacity(capacity(free=299), stricter, initialized=True)
    cannot_fit = parse(config(limits={"reserve_bytes": 512 * MIB}))
    with pytest.raises(ERROR, match="capacity outside bounds"):
        M.validate_capacity(capacity(), cannot_fit, initialized=False)


@pytest.mark.parametrize("limits", [
    [], {"unknown": 1}, {"candidate_bytes": True}, {"candidate_bytes": 0},
    {"candidate_bytes": 268435457}, {"artifact_bytes": 268435456},
    {"reserve_bytes": 1}, {"check_cooldown": 1}, {"journal_bytes": 4194305},
    {"reserve_bytes": 256 * MIB - 1}, {"check_cooldown": 59},
    {"reserve_bytes": 1024 * MIB + 1}, {"check_cooldown": 1024 * MIB + 1},
    {"reserve_bytes": True}, {"check_cooldown": True},
])
def test_limits_refuse_unknown_invalid_expansion_and_unsafe_floors(limits):
    with pytest.raises(ERROR):
        parse(config(limits=limits))


@pytest.mark.parametrize("changes", [
    {"extra": 1}, {"version": True}, {"version": 1},
    {"application_uid": True}, {"application_uid": 975},
    {"application_data_dir": "/etc"}, {"cache_dir": "/var/lib/strugglebus"},
    {"release_repository": "NZCypher819/strugglebus"},
    {"source_repository": "NZCypher819/strugglebus-releases"},
    # One half of each place is not a place.
    {"release_repository": "u64a/strugglebus"},
    {"source_repository": "u64a/strugglebus"},
    {"release_repository": "someone/else", "source_repository": "someone/else"},
])
def test_configuration_refuses_ambiguous_or_unbound_inputs(changes):
    with pytest.raises(ERROR):
        parse(config(**changes))


def test_configuration_may_name_the_projects_repository_or_the_former_place():
    assert parse(config()) == M.LIMITS
    moved = config(release_repository="u64a/strugglebus", source_repository="u64a/strugglebus")
    assert parse(moved) == M.LIMITS


@pytest.mark.parametrize("content", [
    b"[]", b'{"version":1,"version":1}', b'{"version":NaN}',
    b'{"version":1.0}', b"x" * 8193,
], ids=["array", "duplicate", "nonfinite", "float", "oversized"])
def test_configuration_strict_bounded_json(content):
    with pytest.raises((ERROR, ValueError)):
        M.validate_config(content, 900, Path("/var/lib/strugglebus"))


@pytest.mark.parametrize("value", ["relative", "/a/../b", "/a//b", "/a/./b", "/a/", "/a b", "/a\nb", "/", None])
def test_safe_paths_refuse_noncanonical_syntax(value):
    with pytest.raises(ERROR):
        M.safe_path(value)


def test_safe_path_accepts_protected_absolute_reference():
    assert M.safe_path("/etc/strugglebus-updater/worker.json") == M.CONFIG


def test_root_ancestors_checked_in_order(monkeypatch):
    visited = []
    monkeypatch.setattr(M, "protected_directory", visited.append)
    target = Path("/etc/strugglebus-updater/worker.json")
    M.protected_ancestors(target)
    assert visited == list(reversed(target.parents))


@pytest.mark.parametrize("changes", [
    {"st_mode": stat.S_IFLNK | 0o777}, {"st_uid": 975},
    {"st_mode": stat.S_IFDIR | 0o775},
])
def test_protected_directory_refuses_links_ownership_and_writes(monkeypatch, changes):
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(st_mode=stat.S_IFDIR | 0o755, **{
        key: value for key, value in changes.items() if key != "st_mode"
    }) if "st_mode" not in changes else metadata(**changes))
    with pytest.raises(ERROR):
        M.protected_directory(Path("/synthetic"))


def test_cache_root_requires_exact_worker_traversal_contract(monkeypatch):
    monkeypatch.setattr(
        Path, "lstat",
        lambda self: metadata(
            st_mode=stat.S_IFDIR | 0o710, st_uid=0, st_gid=M.WORKER_ID,
        ),
    )
    M.protected_cache_root(M.CACHE)


@pytest.mark.parametrize("changes", [
    {"st_mode": stat.S_IFLNK | 0o710},
    {"st_mode": stat.S_IFDIR | 0o700},
    {"st_mode": stat.S_IFDIR | 0o750},
    {"st_uid": M.WORKER_ID},
    {"st_gid": 0},
])
def test_cache_root_refuses_wrong_type_owner_group_or_mode(monkeypatch, changes):
    values = {
        "st_mode": stat.S_IFDIR | 0o710,
        "st_uid": 0,
        "st_gid": M.WORKER_ID,
    } | changes
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(**values))
    with pytest.raises(ERROR, match="unsafe cache mount root"):
        M.protected_cache_root(M.CACHE)


def test_protected_file_validates_metadata_without_reading_secret(monkeypatch):
    monkeypatch.setattr(M, "protected_ancestors", lambda path: None)
    monkeypatch.setattr(Path, "lstat", lambda self: metadata())
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("credential must not be read"))
    assert M.protected_file(Path("/secret"), modes={0o600}, maximum=65536).st_uid == 0


@pytest.mark.parametrize("changes", [
    {"st_mode": stat.S_IFLNK | 0o600}, {"st_uid": 975}, {"st_nlink": 2},
    {"st_size": 0}, {"st_size": 65537}, {"st_mode": stat.S_IFREG | 0o644},
])
def test_protected_file_rejects_metadata(monkeypatch, changes):
    monkeypatch.setattr(M, "protected_ancestors", lambda path: None)
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(**changes))
    with pytest.raises(ERROR):
        M.protected_file(Path("/secret"), modes={0o600}, maximum=65536)


def test_bounded_read_checks_descriptor_identity_and_length(monkeypatch, tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(b"bounded")
    monkeypatch.setattr(M, "protected_file", lambda *args, **kwargs: metadata())
    monkeypatch.setattr(M.os, "O_NOFOLLOW", 0, raising=False)
    monkeypatch.setattr(M.os, "O_NONBLOCK", 0, raising=False)
    monkeypatch.setattr(M.os, "fstat", lambda descriptor: metadata())
    assert M.read_protected(path, 32, {0o600}) == b"bounded"
    monkeypatch.setattr(M.os, "fstat", lambda descriptor: metadata(st_ino=2))
    with pytest.raises(ERROR, match="changed"):
        M.read_protected(path, 32, {0o600})
    monkeypatch.setattr(M.os, "fstat", lambda descriptor: metadata(st_size=1))
    with pytest.raises(ERROR, match="exceeds"):
        M.read_protected(path, 3, {0o600})


def worker(**changes):
    return SimpleNamespace(**(
        dict(pw_name=M.WORKER, pw_uid=975, pw_gid=975, pw_shell="/usr/sbin/nologin")
        | changes
    ))


def group(**changes):
    return SimpleNamespace(**(dict(gr_name=M.WORKER, gr_gid=975, gr_mem=[]) | changes))


def test_accounts_require_existing_bus_and_unshared_reserved_identity(monkeypatch):
    bus = worker(pw_name="bus", pw_uid=900, pw_gid=901)
    bus_group = group(gr_name="bus", gr_gid=901)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(
        getpwnam=lambda name: bus, getpwall=lambda: [bus, worker()],
    ))
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(
        getgrnam=lambda name: bus_group, getgrall=lambda: [bus_group, group()],
    ))
    assert M.validate_accounts("bus", "bus") == (900, 901)
    with pytest.raises(ERROR):
        M.validate_accounts(M.WORKER, "bus")
    bus.pw_uid = 0
    with pytest.raises(ERROR):
        M.validate_accounts("bus", "bus")


@pytest.mark.parametrize("changes", [
    {"pw_name": "other"}, {"pw_uid": 900}, {"pw_gid": 901}, {"pw_shell": "/bin/sh"},
    {"pw_name": "other", "pw_uid": 900},
])
def test_worker_identity_collisions_refused(changes):
    with pytest.raises(ERROR):
        M.validate_worker_users([worker(**changes)])


@pytest.mark.parametrize("changes", [
    {"gr_name": "other"}, {"gr_gid": 901}, {"gr_mem": ["bus"]},
    {"gr_name": "bus", "gr_gid": 901, "gr_mem": [M.WORKER]},
])
def test_worker_group_collisions_and_supplementary_memberships_refused(changes):
    with pytest.raises(ERROR):
        M.validate_worker_groups([group(**changes)])


def test_absent_worker_identity_is_createable():
    M.validate_worker_users([])
    M.validate_worker_groups([])


def test_exact_dedicated_mount(device_numbers):
    records = M.mount_records(mount_line())
    assert M.cache_mount(records, 2051)["kind"] == "ext4"


@pytest.mark.parametrize("changes", [
    {"kind": "tmpfs"}, {"root": "/bound"}, {"device": "8:4"},
    {"options": "rw,nodev,nosuid"}, {"target": "/elsewhere"},
])
def test_mount_refuses_volatile_bound_wrong_device_or_options(device_numbers, changes):
    with pytest.raises(ERROR):
        M.cache_mount(M.mount_records(mount_line(**changes)), 2051)


@pytest.mark.parametrize("extra", [
    mount_line(), mount_line(target=str(M.CACHE) + "/nested", device="8:4"),
    mount_line(target="/alias"),
])
def test_mount_refuses_aliases_and_nested_mounts(device_numbers, extra):
    with pytest.raises(ERROR):
        M.cache_mount(M.mount_records(mount_line() + extra), 2051)


@pytest.mark.parametrize("content", ["bad topology", "x" * (1024 * 1024 + 1)], ids=["malformed", "oversized"])
def test_mount_metadata_is_bounded_and_strict(content):
    with pytest.raises(ERROR):
        M.mount_records(content)


def test_persistence_matches_uuid_to_actual_block_device(monkeypatch):
    monkeypatch.setattr(Path, "stat", lambda self: metadata(st_mode=stat.S_IFBLK | 0o600))
    M.persistent_mount("# protected fixture\n\n" + fstab(), 2051)


@pytest.mark.parametrize("content", [
    "", fstab() * 2, fstab(source="/dev/sda3"), fstab(kind="tmpfs"),
    fstab(options="rw,nodev,nosuid,noexec,noauto"), fstab(options="defaults"),
    fstab().rstrip() + " extra", "x" * 65537,
], ids=["absent", "duplicate", "non-UUID", "tmpfs", "noauto", "defaults", "fields", "oversized"])
def test_persistence_refuses_unproven_or_unsafe_mounts(content):
    with pytest.raises(ERROR):
        M.persistent_mount(content, 2051)


def test_persistence_refuses_device_substitution(monkeypatch):
    monkeypatch.setattr(Path, "stat", lambda self: metadata(st_mode=stat.S_IFBLK | 0o600, st_rdev=2052))
    with pytest.raises(ERROR):
        M.persistent_mount(fstab(), 2051)


@pytest.mark.parametrize("option", [
    "exec", "suid", "dev", "defaults", "user", "owner", "group",
    "nofail", "x-systemd.automount", "bind", "unknown",
])
def test_persistent_options_cannot_weaken_isolation_at_reboot(option):
    with pytest.raises(ERROR):
        M.persistent_mount(fstab(options="rw,nodev,nosuid,noexec," + option), 2051)


def capacity(total=1024, free=900):
    return SimpleNamespace(f_blocks=total, f_bavail=free, f_frsize=MIB)


def test_capacity_checks_real_total_initial_space_and_rerun_reserve():
    assert M.validate_capacity(capacity(), M.LIMITS, initialized=False)["capacity_bytes"] == 1024 * MIB
    M.validate_capacity(capacity(free=256), M.LIMITS, initialized=True)
    for observation, initialized in [
        (capacity(total=2048), False), (capacity(total=700), False),
        (capacity(free=770), False), (capacity(free=255), True),
    ]:
        with pytest.raises(ERROR):
            M.validate_capacity(observation, M.LIMITS, initialized=initialized)


def fake_layout(monkeypatch, names=(), state=None, lost=()):
    monkeypatch.setattr(M, "protected_ancestors", lambda path: None)
    monkeypatch.setattr(M, "protected_cache_root", lambda path: None)
    monkeypatch.setattr(M, "protected_directory", lambda path: None)
    monkeypatch.setattr(M, "cache_admission", lambda path: True)
    monkeypatch.setattr(Path, "iterdir", lambda self: iter(
        [self / name for name in (lost if self.name == "lost+found" else names)]
    ))
    monkeypatch.setattr(Path, "lstat", lambda self: state or metadata(
        st_mode=stat.S_IFDIR | 0o700, st_uid=975, st_gid=975,
    ))


def test_cache_layout_allows_empty_or_exact_owned_state(monkeypatch):
    fake_layout(monkeypatch)
    assert not M.cache_layout()
    fake_layout(monkeypatch, names=("state", "lost+found"))
    assert M.cache_layout()
    monkeypatch.setattr(M, "cache_admission", lambda path: False)
    assert not M.cache_layout()


@pytest.mark.parametrize("names,initialized", [
    ((), False), (("updater-worker.lock",), False),
    (("updater-journal.json", "operation-owned"), True),
])
def test_cache_admission_requires_pristine_state_before_init(monkeypatch, names, initialized):
    path = Path("/cache/state")
    monkeypatch.setattr(Path, "iterdir", lambda self: iter(self / name for name in names))

    def observed(entry):
        if entry.name not in names:
            raise FileNotFoundError
        return metadata(st_mode=stat.S_IFREG | 0o600, st_uid=975, st_gid=975, st_size=0)

    monkeypatch.setattr(Path, "lstat", observed)
    assert M.cache_admission(path) is initialized


@pytest.mark.parametrize("name,changes", [
    ("operation-orphaned", {}),
    ("updater-worker.lock", {"st_mode": stat.S_IFLNK | 0o600}),
    ("updater-worker.lock", {"st_mode": stat.S_IFREG | 0o644}),
    ("updater-worker.lock", {"st_uid": 900}),
    ("updater-worker.lock", {"st_gid": 901}),
    ("updater-worker.lock", {"st_nlink": 2}),
    ("updater-worker.lock", {"st_size": 1}),
])
def test_cache_admission_refuses_nonpristine_missing_history(monkeypatch, name, changes):
    monkeypatch.setattr(Path, "iterdir", lambda self: iter([self / name]))
    values = dict(st_mode=stat.S_IFREG | 0o600, st_uid=975, st_gid=975, st_size=0)

    def observed(entry):
        if entry.name == "updater-journal.json":
            raise FileNotFoundError
        return metadata(**(values | changes))

    monkeypatch.setattr(Path, "lstat", observed)
    with pytest.raises(ERROR):
        M.cache_admission(Path("/cache/state"))


@pytest.mark.parametrize("names,state,lost", [
    (("unrelated",), None, ()), (("lost+found",), None, ("recovered",)),
    (("state",), metadata(st_mode=stat.S_IFDIR | 0o777), ()),
    (("state",), metadata(st_mode=stat.S_IFLNK | 0o700), ()),
])
def test_cache_layout_refuses_foreign_data_and_unsafe_state(monkeypatch, names, state, lost):
    fake_layout(monkeypatch, names, state, lost)
    with pytest.raises(ERROR):
        M.cache_layout()


def storage_observations(monkeypatch, device_numbers):
    monkeypatch.setattr(M, "cache_layout", lambda: False)
    monkeypatch.setattr(Path, "stat", lambda self: (
        metadata(st_mode=stat.S_IFBLK | 0o600) if str(self).endswith("cache")
        else metadata(st_dev=2051 if self == M.CACHE else 2052)
    ))
    monkeypatch.setattr(Path, "read_text", lambda self: (
        mount_line() if self.name == "mountinfo" else "2097152"
    ))
    monkeypatch.setattr(M, "read_protected", lambda *args: fstab().encode())
    monkeypatch.setattr(M, "persistent_mount", lambda *args: None)
    monkeypatch.setattr(M.os, "statvfs", lambda path: capacity(), raising=False)
    monkeypatch.setattr(M, "container_manager", lambda: None)


def test_complete_storage_probe_uses_kernel_capacity_and_persistent_topology(monkeypatch, device_numbers):
    storage_observations(monkeypatch, device_numbers)
    result = M.inspect_storage(Path("/var/lib/strugglebus"), M.LIMITS)
    assert result["available_bytes"] == 900 * MIB


def test_lxc_mount_point_needs_no_guest_block_node_or_fstab(monkeypatch, device_numbers):
    storage_observations(monkeypatch, device_numbers)
    monkeypatch.setattr(M, "container_manager", lambda: "lxc")
    monkeypatch.setattr(M, "persistent_mount", lambda *args: pytest.fail("LXC has no guest fstab"))
    monkeypatch.setattr(Path, "stat", lambda self, **kwargs: (
        pytest.fail("LXC has no guest block node") if str(self).startswith("/dev/")
        else metadata(st_dev=2051 if self == M.CACHE else 2052)
    ))
    assert M.inspect_storage(Path("/var/lib/strugglebus"), M.LIMITS)["available_bytes"] == 900 * MIB
    # Dedicated mount, separation and the 1 GiB ceiling still apply.
    with pytest.raises(ERROR, match="shares"):
        M.inspect_storage(M.CACHE, M.LIMITS)
    monkeypatch.setattr(Path, "read_text", lambda self: (
        mount_line() if self.name == "mountinfo" else "4194304"
    ))
    with pytest.raises(ERROR, match="block device"):
        M.inspect_storage(Path("/var/lib/strugglebus"), M.LIMITS)


@pytest.mark.parametrize("observed,expected", [
    (FileNotFoundError, None),
    (metadata(st_mode=stat.S_IFREG | 0o444, st_size=4), "lxc"),
    (metadata(st_mode=stat.S_IFREG | 0o666, st_size=4), ERROR),
    (metadata(st_mode=stat.S_IFREG | 0o444, st_uid=1000, st_size=4), ERROR),
    (metadata(st_mode=stat.S_IFLNK | 0o777, st_size=4), ERROR),
])
def test_container_marker_must_be_root_protected(monkeypatch, observed, expected):
    def lstat(self):
        assert self == Path("/run/systemd/container")
        if observed is FileNotFoundError:
            raise FileNotFoundError(self)
        return observed
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: "lxc\n")
    if expected is ERROR:
        with pytest.raises(ERROR, match="container marker"):
            M.container_manager()
    else:
        assert M.container_manager() == expected


def test_storage_probe_refuses_same_device_and_oversized_block(monkeypatch, device_numbers):
    storage_observations(monkeypatch, device_numbers)
    with pytest.raises(ERROR, match="shares"):
        M.inspect_storage(M.CACHE, M.LIMITS)
    monkeypatch.setattr(Path, "read_text", lambda self: (
        mount_line() if self.name == "mountinfo" else "4194304"
    ))
    with pytest.raises(ERROR, match="block device"):
        M.inspect_storage(Path("/var/lib/strugglebus"), M.LIMITS)


def host_observations(monkeypatch):
    monkeypatch.setattr(M, "validate_accounts", lambda *args: (900, 901))
    monkeypatch.setattr(M, "protected_file", lambda *args, **kwargs: metadata())
    monkeypatch.setattr(M, "read_protected", lambda *args: json.dumps(config()).encode())
    monkeypatch.setattr(M, "protected_ancestors", lambda path: None)
    monkeypatch.setattr(M, "protected_directory", lambda path: None)
    monkeypatch.setattr(M, "inspect_runtime", lambda gid: None)
    synthetic_acl_absence(monkeypatch)
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(
        st_mode=stat.S_IFDIR | 0o750, st_uid=900, st_gid=901,
    ))
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(M, "inspect_storage", lambda *args: {
        "capacity_bytes": 1024 * MIB, "available_bytes": 900 * MIB,
    })


def inspect_host():
    return M.inspect(
        M.CONFIG, "bus", "bus", Path("/var/lib/strugglebus"),
    )


def test_host_probe_returns_only_nonsecret_capacity(monkeypatch):
    host_observations(monkeypatch)
    assert inspect_host() == {
        "version": 1, "application_uid": 900, "application_gid": 901,
        "capacity_bytes": 1024 * MIB, "available_bytes": 900 * MIB,
    }


def synthetic_acl_absence(monkeypatch):
    monkeypatch.setattr(M.errno, "ENODATA", 61, raising=False)

    def absent(path, name, *, follow_symlinks):
        assert follow_symlinks is False
        raise OSError(61, "synthetic absent ACL")

    monkeypatch.setattr(M.os, "getxattr", absent, raising=False)


def test_acl_absence_requires_both_explicit_enodata_results_without_following_links(monkeypatch):
    synthetic_acl_absence(monkeypatch)
    calls = []

    def absent(path, name, *, follow_symlinks):
        calls.append((path, name, follow_symlinks))
        raise OSError(61, "synthetic absent ACL")

    monkeypatch.setattr(M.os, "getxattr", absent)
    path = Path("/var/lib/strugglebus")
    M.require_no_data_acls(path)
    assert calls == [
        (path, "system.posix_acl_access", False),
        (path, "system.posix_acl_default", False),
    ]


@pytest.mark.parametrize("attribute", ["system.posix_acl_access", "system.posix_acl_default"])
@pytest.mark.parametrize("value", [b"", b"synthetic named worker ACL"])
def test_access_or_default_acl_presence_refuses_even_empty_values(monkeypatch, attribute, value):
    synthetic_acl_absence(monkeypatch)

    def observed(path, name, *, follow_symlinks):
        if name == attribute:
            return value
        raise OSError(61, "synthetic absent ACL")

    monkeypatch.setattr(M.os, "getxattr", observed)
    with pytest.raises(ERROR, match="ACLs are not permitted"):
        M.require_no_data_acls(Path("/var/lib/strugglebus"))


@pytest.mark.parametrize("failure", [
    OSError(1, "permission denied"), OSError(13, "access denied"),
    OSError(95, "unsupported"), OSError(5, "I/O failure"),
    OSError("no explicit absence proof"), NotImplementedError("unsupported API"),
])
def test_acl_query_failure_is_not_absence_proof(monkeypatch, failure):
    synthetic_acl_absence(monkeypatch)

    def failed(path, name, *, follow_symlinks):
        raise failure

    monkeypatch.setattr(M.os, "getxattr", failed)
    with pytest.raises(ERROR, match="ACL proof unavailable"):
        M.require_no_data_acls(Path("/var/lib/strugglebus"))


@pytest.mark.parametrize("missing", ["getxattr", "ENODATA"])
def test_acl_missing_platform_support_fails_closed(monkeypatch, missing):
    synthetic_acl_absence(monkeypatch)
    target = M.os if missing == "getxattr" else M.errno
    monkeypatch.delattr(target, missing)
    with pytest.raises(ERROR, match="ACL proof unavailable"):
        M.require_no_data_acls(Path("/var/lib/strugglebus"))


def test_host_preflight_rejects_acl_before_storage_or_worker_admission(monkeypatch):
    host_observations(monkeypatch)
    monkeypatch.setattr(M.os, "getxattr", lambda *args, **kwargs: b"named-worker")
    monkeypatch.setattr(M, "inspect_storage", lambda *args: pytest.fail("ACL must gate storage admission"))
    with pytest.raises(ERROR, match="ACLs are not permitted"):
        inspect_host()


def test_host_probe_refuses_application_owned_config(monkeypatch):
    host_observations(monkeypatch)
    monkeypatch.setattr(M, "protected_file", lambda *args, **kwargs: metadata(st_gid=901))
    with pytest.raises(ERROR):
        inspect_host()


def test_socket_parent_and_existing_socket_are_root_managed(monkeypatch):
    monkeypatch.setattr(M, "protected_ancestors", lambda path: None)
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    M.inspect_runtime(901)
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(Path, "lstat", lambda self: (
        metadata(st_mode=stat.S_IFSOCK | 0o660, st_gid=901)
        if self.name == "worker.sock" else metadata(st_mode=stat.S_IFDIR | 0o755)
    ))
    M.inspect_runtime(901)
    monkeypatch.setattr(Path, "exists", lambda self: self.name != "worker.sock")
    M.inspect_runtime(901)
    monkeypatch.setattr(Path, "exists", lambda self: True)
    with pytest.raises(ERROR, match="socket"):
        M.inspect_runtime(902)
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(st_mode=stat.S_IFDIR | 0o775))
    with pytest.raises(ERROR, match="parent"):
        M.inspect_runtime(901)


def test_code_entries_allow_only_root_readonly_files_directories_and_exact_lib64(monkeypatch):
    root = Path("/opt/strugglebus-updater/releases/1.2.3")
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(st_mode=stat.S_IFDIR | 0o755))
    M.validate_code_entry(root / "venv", root)
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(st_mode=stat.S_IFREG | 0o644))
    M.validate_code_entry(root / "venv/worker.py", root)
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(st_mode=stat.S_IFLNK | 0o777))
    monkeypatch.setattr(M.os, "readlink", lambda path: "lib")
    M.validate_code_entry(root / "venv/lib64", root)
    with pytest.raises(ERROR):
        M.validate_code_entry(root / "venv/other-link", root)
    monkeypatch.setattr(M.os, "readlink", lambda path: "/mutable")
    with pytest.raises(ERROR):
        M.validate_code_entry(root / "venv/lib64", root)


@pytest.mark.parametrize("changes", [
    {"st_uid": 975}, {"st_mode": stat.S_IFREG | 0o664}, {"st_nlink": 2},
])
def test_code_entries_refuse_mutable_or_linked_content(monkeypatch, changes):
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(**changes))
    with pytest.raises(ERROR):
        M.validate_code_entry(Path("/code/file"), Path("/code"))


def test_complete_code_probe_is_readonly_and_requires_installed_worker(monkeypatch):
    root = Path("/opt/strugglebus-updater/releases/1.2.3")
    monkeypatch.setattr(M, "protected_ancestors", lambda path: None)
    monkeypatch.setattr(M, "protected_directory", lambda path: None)
    monkeypatch.setattr(M.os, "walk", lambda *args, **kwargs: [(str(root), ["venv"], ["approved.whl"])])
    monkeypatch.setattr(Path, "lstat", lambda self: metadata(st_mode=stat.S_IFREG | 0o755))
    assert M.verify_code(root) == {"version": 1, "files_checked": 2}
    with pytest.raises(ERROR):
        M.verify_code(Path("/opt/strugglebus/current"))
    monkeypatch.setattr(M.os, "walk", lambda *args, **kwargs: [(str(root), [], ["file"] * 100001)])
    with pytest.raises(ERROR, match="inventory"):
        M.verify_code(root)


def test_cli_is_static_on_failure_and_has_no_secret_testing_or_quota_flags(monkeypatch, capsys):
    monkeypatch.setattr(M, "inspect", lambda *args: {"version": 1})
    args = [
        "host", "--config", "/etc/strugglebus-updater/worker.json",
        "--application-user", "bus", "--application-group", "bus",
        "--application-data-dir", "/var/lib/strugglebus",
    ]
    assert M.main(args) == 0
    assert json.loads(capsys.readouterr().out) == {"version": 1}
    monkeypatch.setattr(M, "inspect", lambda *args: (_ for _ in ()).throw(OSError("secret sentinel")))
    assert M.main(args) == 1
    output = capsys.readouterr()
    assert output.err == '{"error":"updater-bootstrap-preflight-refused"}\n'
    assert "sentinel" not in output.err
    monkeypatch.setattr(M, "verify_code", lambda *args: {"version": 1, "files_checked": 2})
    assert M.main(["code", "--release-root", "/opt/strugglebus-updater/releases/1.2.3"]) == 0
    with pytest.raises(SystemExit):
        M.main(args + ["--quota-verified"])
