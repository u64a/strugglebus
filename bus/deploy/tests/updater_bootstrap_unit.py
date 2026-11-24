"""Offline structural contracts; deliberately not a systemd/host qualification."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re


DEPLOY = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (DEPLOY / relative).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_markers(content: str, markers: tuple[str, ...]) -> None:
    for marker in markers:
        if marker not in content:
            raise AssertionError("missing updater deployment safety marker: " + marker)


def validate_bootstrap(bootstrap: str, tasks: str, install: str) -> None:
    source = DEPLOY / "files/strugglebus_updater_preflight.py"
    match = re.search(r"updater_helper_sha256: ([0-9a-f]{64})", bootstrap)
    require(
        match is not None and match[1] == hashlib.sha256(source.read_bytes()).hexdigest(),
        "updater preflight checksum is missing or mismatched",
    )
    require_markers(bootstrap, (
        "bootstrap-updater-", "strugglebus_assert_qualified_updater_bootstrap",
        "tasks_from: resolve_release_assets.yml", "strugglebus_updater_source_commit",
        "strugglebus_updater_source_tree", "strugglebus_updater_manifest_sha256",
    ))
    for name in ("configure", "bootstrap", "maintenance_deploy"):
        require(
            "updater_bootstrap" not in read(f"playbooks/{name}.yml"),
            "ordinary deployment must not invoke updater bootstrap",
        )
        require(
            "name: updater" not in read(f"playbooks/{name}.yml"),
            "ordinary deployment must not invoke the updater role",
        )
    for content in (bootstrap, tasks, install):
        for forbidden in (
            "strugglebus_release_action: deploy", "strugglebus_release_action: maintenance",
            "strugglebus_release_action: initial_install", "state: restarted",
            "Restart Strugglebus", "name: strugglebus.service", "ansible.builtin.mount",
            "ansible.posix.mount", "ansible.builtin.shell", "strugglebus_updater_socket_path:",
            "strugglebus_current_link", "sqlite3", "vzdump",
        ):
            require(forbidden not in content, "forbidden updater bootstrap action: " + forbidden)


def validate_installation(tasks: str, install: str) -> None:
    require_markers(tasks, (
        "uid: 975", "gid: 975", 'groups: ""', "append: false",
        "shell: /usr/sbin/nologin", "mode: \"0700\"", "- --config",
        "name: strugglebus-updater.socket", "state: started",
    ))
    require(
        tasks.index("Verify existing identities") < tasks.index("Create the dedicated"),
        "updater identity verification must precede creation",
    )
    require(
        tasks.index("Initialize pristine storage") < tasks.index("Enable only the updater socket"),
        "updater history verification must precede socket activation",
    )
    require_markers(install, (
        "--copies", "--require-hashes", "--only-binary", "--no-build", "--no-deps",
        "--no-index", "UV_NO_CACHE", "UV_LINK_MODE: copy",
        "Verify complete installed code ownership", "updater_install_identity",
    ))
    dependency_sync = install[
        install.index(
            "- name: Install only hash-locked binary dependencies without source builds"
        ):
        install.index(
            "- name: Install only the approved worker wheel without dependency resolution"
        )
    ]
    require(
        "--only-binary" in dependency_sync and "--no-build" not in dependency_sync,
        "dependency sync must use uv's compatible binary-only admission",
    )


def validate_history(tasks: str) -> None:
    require_markers(tasks, (
        "path: /var/lib/strugglebus-updater-cache/state/updater-journal.json",
        "updater_journal.stat.isreg | default(false)",
        "not (updater_journal.stat.islnk | default(true))",
        "updater_journal.stat.uid | default(-1) == 975",
        "updater_journal.stat.gid | default(-1) == 975",
        "updater_journal.stat.nlink | default(0) == 1",
        "updater_journal.stat.mode | default('') == '0600'",
        "updater_journal.stat.size | default(4194305) <= 4194304",
        "'status' if updater_journal.stat.exists else 'init'",
        '- "{{ updater_history_action }}"',
        "updater_existing_units.results | selectattr('stat.exists') | list | length == 0",
        "when: updater_active.rc != 0",
    ))
    require(
        tasks.index("Refuse missing history") < tasks.index("Initialize pristine storage"),
        "missing updater history must be refused before initialization",
    )
    require(
        tasks.index("Refuse unsafe existing journal") < tasks.index("Initialize pristine storage"),
        "unsafe updater history must be refused before initialization",
    )
    require(
        "rescue:" not in tasks and "failed_when: false" not in tasks,
        "updater history failures must not be ignored or reset",
    )


def validate_units(service: str, socket: str) -> None:
    require_markers(service, (
        "User=strugglebus-updater", "Group=strugglebus-updater", "SupplementaryGroups=\n",
        "-I -m strugglebus.update_worker serve --config",
        "ProtectSystem=strict", "NoNewPrivileges=true", "SocketBindDeny=any",
        "ReadWritePaths=/var/lib/strugglebus-updater-cache/state",
        "MemoryMax=512M", "MemorySwapMax=0", "TasksMax=16", "CPUQuota=25%",
        "CPUWeight=10", "IOWeight=10", "KillMode=mixed", "LimitCORE=0",
    ))
    require("LoadCredential=" not in service, "public updater must not project credentials")
    require("~@kill" not in service, "worker must retain termination of its owned job")
    require("STRUGGLEBUS_ADMIN" not in service, "worker must not receive bus admin credentials")
    require(
        "Requires=strugglebus-updater" not in read("roles/systemd/templates/strugglebus.service.j2"),
        "bus service must not depend on the updater",
    )
    require_markers(socket, (
        "ListenStream=/run/strugglebus-updater/worker.sock", "SocketUser=root",
        "SocketGroup={{ strugglebus_service_group }}", "SocketMode=0660",
        "DirectoryMode=0755", "Accept=no", "Backlog=4",
    ))
    require(
        "ListenStream=0" not in socket and "ListenStream=[" not in socket,
        "updater must not bind an inbound TCP listener",
    )


def main() -> int:
    bootstrap = read("playbooks/updater_bootstrap.yml")
    tasks = read("roles/updater/tasks/main.yml")
    install = read("roles/updater/tasks/install.yml")
    service = read("roles/updater/templates/strugglebus-updater.service.j2")
    socket = read("roles/updater/templates/strugglebus-updater.socket.j2")
    validate_bootstrap(bootstrap, tasks, install)
    validate_installation(tasks, install)
    validate_history(tasks)
    validate_units(service, socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
