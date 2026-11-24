from pathlib import Path


ROOT = Path(__file__).parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_adoption_is_explicit_version_bound_and_non_default():
    play = read("deploy/playbooks/self_update_adopt.yml")
    tasks = read("deploy/roles/self_update/tasks/main.yml")
    assert "adopt-self-update-" in play
    assert "strugglebus_self_update_version" in play
    assert "strugglebus_self_update_minimum_free_bytes: 5368709120" in play
    assert "operation.json" in tasks
    assert "phase == 'complete'" in tasks
    assert "/usr/bin/df" in tasks
    assert "/etc/strugglebus-updater/worker.json" in tasks
    assert ").version == 2" in tasks
    assert "NZCypher819/strugglebus-releases" in tasks
    assert "NZCypher819/strugglebus" in tasks
    assert tasks.index("worker configuration before adoption") < tasks.index(
        "Publish the selected updater release"
    )
    assert "/usr/bin/readlink" in tasks
    assert "--canonicalize-existing" in tasks
    assert "self_update_current_release.stdout" in tasks
    assert "strugglebus-maintenance.timer" in tasks


def test_adoption_leaves_socket_activated_worker_idle():
    tasks = read("deploy/roles/self_update/tasks/main.yml")
    marker = (
        "- name: Leave the socket-activated worker stopped until an approved "
        "IPC request arrives"
    )
    body = tasks.split(marker, 1)[1].split("\n- name:", 1)[0]
    assert "name: strugglebus-updater.service" in body
    assert "state: stopped" in body
    assert "state: restarted" not in body


def test_maintenance_units_keep_control_and_execution_separate():
    control = read(
        "deploy/roles/self_update/templates/strugglebus-maintenance.service.j2",
    )
    run = read(
        "deploy/roles/self_update/templates/strugglebus-maintenance-run.service.j2",
    )
    socket = read(
        "deploy/roles/self_update/templates/strugglebus-maintenance.socket.j2",
    )
    timer = read(
        "deploy/roles/self_update/templates/strugglebus-maintenance.timer.j2",
    )
    assert "maintenance_daemon serve" in control
    assert "RestrictAddressFamilies=AF_UNIX" in control
    assert "maintenance_daemon run" in run
    assert "ProtectSystem=strict" in run
    assert "ReadWritePaths=" in run
    # systemd 257 drops CAP_SETUID for an explicit User=root, which breaks the
    # setpriv/runuser privilege drop used by the notice and install helpers.
    assert "\nUser=" not in run
    assert "\nGroup=" not in run
    read_only = next(line for line in run.splitlines() if line.startswith("ReadOnlyPaths="))
    read_write = next(line for line in run.splitlines() if line.startswith("ReadWritePaths="))
    # A path listed in both is mounted read-only; the updater root must be writable.
    assert "/opt/strugglebus-updater" not in read_only
    assert "/opt/strugglebus-updater" in read_write.split()
    # Activation renames a link onto the current-link path, so its parent is writable.
    assert "{{ strugglebus_current_link | dirname }}" in read_write
    assert "/usr/local/libexec/strugglebus-maintenance" in read_write.split()
    # The helper's listener ownership check uses ss, which needs sock_diag.
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in run
    tasks = read("deploy/roles/self_update/tasks/main.yml")
    assert "path: /usr/local/libexec/strugglebus-maintenance" in tasks
    assert "SocketUser=root" in socket
    assert "SocketMode=0660" in socket
    assert "OnCalendar=*-*-* *:*:00" in timer
    assert "Persistent=true" in timer


def test_application_receives_only_the_protected_maintenance_socket():
    unit = read("deploy/roles/systemd/templates/strugglebus.service.j2")
    config = read("deploy/roles/self_update/templates/maintenance.json.j2")
    assert "'maintenance_socket_path'" in unit
    assert "STRUGGLEBUS_{{ setting | upper }}" in unit
    assert '"application_uid"' in config
    assert '"updater_socket"' in config
    assert '"health_url"' in config
    assert '"ca_path"' in config
    assert "credential" not in config.lower()


def test_adopted_updater_reads_public_releases_without_credentials():
    unit = read("deploy/roles/self_update/templates/strugglebus-updater.service.j2")
    assert "LoadCredential=" not in unit
    assert "CREDENTIALS_DIRECTORY" not in unit
    assert "-I -m strugglebus.update_worker serve --config" in unit
