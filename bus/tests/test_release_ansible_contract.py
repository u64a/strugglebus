from pathlib import Path
import runpy

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
RESOLVER = (
    REPOSITORY / "deploy/roles/release/tasks/resolve_release_assets.yml"
).read_text(encoding="utf-8")
MAIN = (REPOSITORY / "deploy/roles/release/tasks/main.yml").read_text(encoding="utf-8")
EXAMPLE = (
    REPOSITORY / "deploy/inventory/example/group_vars/all.yml"
).read_text(encoding="utf-8")
BOOTSTRAP = (REPOSITORY / "deploy/playbooks/bootstrap.yml").read_text(encoding="utf-8")
INITIAL_INSTALL = (
    REPOSITORY / "deploy/roles/release/tasks/initial_install.yml"
).read_text(encoding="utf-8")
MAINTENANCE = (
    REPOSITORY / "deploy/roles/release/tasks/maintenance.yml"
).read_text(encoding="utf-8")
MAINTENANCE_PLAYBOOK = (
    REPOSITORY / "deploy/playbooks/maintenance_deploy.yml"
).read_text(encoding="utf-8")
MAINTENANCE_HELPER = (
    REPOSITORY / "deploy/roles/guest_base/files/strugglebus-maintenance.py"
).read_text(encoding="utf-8")
MAINTENANCE_CONFIGURATION = (
    REPOSITORY / "deploy/roles/release/tasks/maintenance_configuration.yml"
).read_text(encoding="utf-8")
DEPLOY_VALIDATOR = (REPOSITORY / "deploy/validate.py").read_text(encoding="utf-8")
TASK_SYNTAX = (
    REPOSITORY / "deploy/tests/release_tasks_syntax.yml"
).read_text(encoding="utf-8")
CADDY = (
    REPOSITORY / "deploy/roles/caddy/templates/Caddyfile.j2"
).read_text(encoding="utf-8")
SYSTEMD = (
    REPOSITORY / "deploy/roles/systemd/templates/strugglebus.service.j2"
).read_text(encoding="utf-8")


def test_systemd_launches_shutdown_aware_service_entry_point() -> None:
    assert "ExecStart={{ strugglebus_current_link }}/venv/bin/strugglebus serve" in SYSTEMD
    assert "venv/bin/uvicorn" not in SYSTEMD


def test_verified_release_directory_is_inert_by_default() -> None:
    assert "resolve_release_assets.yml" in MAIN
    assert "strugglebus_verified_release_dir" not in EXAMPLE
    assert "strugglebus_assert_authenticated_github_acquisition" not in EXAMPLE
    assert "strugglebus_assert_immutable_github_release" not in EXAMPLE
    assert 'in ["initial_install", "maintenance"]' in MAIN


def test_verified_release_directory_rejects_ambiguous_legacy_inputs() -> None:
    for variable in (
        "strugglebus_wheel_src",
        "strugglebus_wheel_sha256",
        "strugglebus_requirements_lock_src",
        "strugglebus_requirements_lock_sha256",
    ):
        assert f"{variable} is not defined" in RESOLVER
    assert "strugglebus_release_version is defined" in RESOLVER


def test_verified_release_directory_requires_authenticated_immutable_acquisition() -> None:
    assert "strugglebus_assert_authenticated_github_acquisition" in RESOLVER
    assert "strugglebus_assert_immutable_github_release" in RESOLVER
    assert "authenticated-github-acquisition-required" in RESOLVER
    assert "sha256-verified" in RESOLVER
    assert (
        "strugglebus_release_version not in "
        "['0.2.5', '0.2.6', '0.2.28', '0.2.31', '0.2.32', '0.2.33', '0.2.34', '0.2.35', '0.2.36', '0.2.37']"
    ) in RESOLVER
    assert "strugglebus_release_source_commit" in RESOLVER
    assert "strugglebus_release_source_tree" in RESOLVER
    assert "strugglebus_release_assets" in RESOLVER
    assert "--minimum-package-version" in RESOLVER


def test_offline_validation_precedes_derived_release_inputs() -> None:
    validate = RESOLVER.index("Validate the optional release directory fully offline")
    require = RESOLVER.index("Require bounded verified release facts")
    derive = RESOLVER.index("Derive existing release inputs")

    assert validate < require < derive
    assert 'NO_PROXY: "*"' in RESOLVER
    assert "release_bundle.py" in RESOLVER


def test_bootstrap_uses_isolated_first_install_contract() -> None:
    assert "strugglebus_release_action: initial_install" in BOOTSTRAP
    assert 'in ["initial_install", "maintenance"]' in MAIN
    assert (
        'in ["initial_install", "maintenance", "prestage", "deploy"]'
        in RESOLVER
    )
    assert "strugglebus_cutover_operation_id" not in INITIAL_INSTALL
    assert "strugglebus_cutover_prestage_sha256" not in INITIAL_INSTALL
    assert 'ca_path: "{{ strugglebus_caddy_ca_path }}"' in INITIAL_INSTALL
    assert "Remove the failed first-release staging link" in INITIAL_INSTALL
    assert (
        'path: "{{ strugglebus_release_root }}/.current-'
        '{{ strugglebus_release_version }}"'
        in INITIAL_INSTALL
    )
    assert "Remove the failed first-release selection" in INITIAL_INSTALL
    assert (
        "Remove mutable state created only by the failed first start"
        in INITIAL_INSTALL
    )


def test_external_tls_compatibility_site_is_explicit_and_default_on() -> None:
    variable = "strugglebus_external_tls_legacy_compatibility_site"
    assert f"{variable}: true" in EXAMPLE
    assert f"{variable} | default(true)" in CADDY
    assert "tls {{ strugglebus_external_cert_path }}" in CADDY
    assert f"{variable} | default(true)" in SYSTEMD


def test_maintenance_action_is_registered_and_validated() -> None:
    assert '"maintenance"' in MAIN
    assert "maintenance.yml" in TASK_SYNTAX
    assert "playbooks/maintenance_deploy.yml" in DEPLOY_VALIDATOR
    assert "strugglebus_release_action: maintenance" in MAINTENANCE_PLAYBOOK


def test_maintenance_never_requires_cutover_handoff_ceremony() -> None:
    # The maintenance window exists to avoid the online-split machinery; it must
    # not silently reintroduce operation IDs, barriers, or pre-stage receipts.
    for ceremony in (
        "strugglebus_cutover_operation_id",
        "strugglebus_cutover_barrier_path",
        "strugglebus_cutover_prestage_sha256",
        "strugglebus_deploy_stopped_path_budget_seconds",
    ):
        assert ceremony not in MAINTENANCE
        assert ceremony not in MAINTENANCE_PLAYBOOK
    assert "strugglebus_cutover" not in MAIN


def test_maintenance_requires_typed_approval_bound_to_the_candidate() -> None:
    approval = "strugglebus_maintenance_approval"
    assert approval in MAINTENANCE
    assert approval in MAINTENANCE_PLAYBOOK
    # The approval must name the exact version, so it cannot be blind-pasted.
    assert "== 'deploy-' + strugglebus_release_version" in MAINTENANCE
    assert "== 'deploy-' + strugglebus_release_version" in MAINTENANCE_PLAYBOOK


def test_maintenance_backs_up_cold_before_switching() -> None:
    lifecycle = MAINTENANCE_HELPER[MAINTENANCE_HELPER.index("def run("):]
    stop = lifecycle.index("host.stop()")
    backup = lifecycle.index('host.snapshot(record["operation_id"], create=True)')
    activate = lifecycle.index("host.activate(record)")
    start = lifecycle.index("host.start()", activate)
    assert stop < backup < activate < start
    assert '"--maintenance-id"' in MAINTENANCE_HELPER
    assert '"--verify-maintenance-id"' in MAINTENANCE_HELPER
    assert "application did not stop" in MAINTENANCE_HELPER
    assert "listener remains occupied" in MAINTENANCE_HELPER
    assert "request['bind_port']" in MAINTENANCE_HELPER
    assert "strugglebus_app_target.split(':')[1]" not in MAINTENANCE


def test_maintenance_verifies_readiness_through_the_configured_ca() -> None:
    assert "strugglebus_health_url" in MAINTENANCE_CONFIGURATION
    assert 'ca_path: "{{ strugglebus_caddy_ca_path }}"' in MAINTENANCE_CONFIGURATION
    assert 'ssl.create_default_context(cafile=self.request["ca_path"])' in MAINTENANCE_HELPER
    assert '{"status": "ok"}' in MAINTENANCE_HELPER
    assert "running release identity mismatch" in MAINTENANCE_HELPER


def test_maintenance_preserves_provenance_without_unsafe_predecessor_fallback() -> None:
    assert "rescue:" in MAINTENANCE
    assert "No predecessor restart or database restoration" in MAINTENANCE
    assert "possible candidate start forbids predecessor selection" in MAINTENANCE_HELPER
    assert "protected manual recovery" in MAINTENANCE_HELPER
    assert "Restore the previous release selection" not in MAINTENANCE


def test_maintenance_refuses_to_replace_first_install() -> None:
    assert "Require an existing installation to upgrade" in MAINTENANCE
    assert "initial_install action for a first activation" in MAINTENANCE


def test_maintenance_check_mode_mutates_nothing() -> None:
    for guarded in (
        "Materialize the exact candidate release before the outage",
        "Install the reviewed certificate renewal helper before the outage",
        "Perform the maintenance window",
    ):
        assert guarded in MAINTENANCE
    assert MAINTENANCE.count("when: not ansible_check_mode") >= 2


def test_maintenance_supplies_backup_inputs_and_restores_backups() -> None:
    assert 'database: "{{ strugglebus_database_path }}"' in MAINTENANCE_CONFIGURATION
    assert 'backup_dir: "{{ strugglebus_backup_dir }}"' in MAINTENANCE_CONFIGURATION
    assert '"stop", "strugglebus-backup.service"' in MAINTENANCE_HELPER
    assert '"enable", "--now", "strugglebus-backup.timer"' in MAINTENANCE_HELPER
    assert '"cleanup-failed"' in MAINTENANCE_HELPER
    assert 'advance("retire-intent")' in MAINTENANCE_HELPER
    assert 'advance("snapshot-ready")' in MAINTENANCE_HELPER


def _load_maintenance_helper():
    import importlib.util

    path = REPOSITORY / "deploy/roles/guest_base/files/strugglebus-maintenance.py"
    spec = importlib.util.spec_from_file_location("maintenance_stop_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _RecordingHost:
    """A Host with only the pieces stop() touches."""

    def __init__(self, states):
        self.request = {"bind_port": 8080}
        self.states = list(states)
        self.issued: list[list[str]] = []
        self.listener = ""

    def command(self, argv, *, timeout=30, allowed=(0,)):
        self.issued.append(argv)
        if argv[:2] == ["systemctl", "is-active"]:
            if argv[2] == "strugglebus-backup.service":
                return "inactive"
            return self.states.pop(0)
        if argv[0] == "ss":
            return self.listener
        return ""


def test_a_killed_stop_is_cleared_and_requalified_rather_than_deadlocking():
    """The v0.2.20 outage: a killed stop left a state no rerun could clear.

    A stop that exceeds TimeoutStopSec ends in SIGKILL, and systemd then reports
    the unit as failed rather than inactive. stop() required inactive, so every
    subsequent attempt read failed again and the operation could never advance.
    Rerunning - the documented recovery - reproduced it exactly.
    """

    module = _load_maintenance_helper()
    host = _RecordingHost(["failed", "inactive"])

    module.Host.stop(host)

    assert ["systemctl", "reset-failed", "strugglebus.service"] in host.issued
    # Quiescence is re-established after the reset, not assumed from it.
    assert host.issued[-1][0] == "ss"


def test_clearing_the_latch_cannot_invent_quiescence():
    """reset-failed only removes a record of how a process exited.

    If the unit is still not stopped afterwards, or the listener is still held,
    the original refusal must stand. Otherwise the fix for the deadlock would
    become a way to run maintenance against a live database.
    """

    module = _load_maintenance_helper()

    still_running = _RecordingHost(["failed", "active"])
    with pytest.raises(module.MaintenanceError, match="did not stop"):
        module.Host.stop(still_running)

    holding_port = _RecordingHost(["failed", "inactive"])
    holding_port.listener = "LISTEN 0 128 127.0.0.1:8080"
    with pytest.raises(module.MaintenanceError, match="listener remains occupied"):
        module.Host.stop(holding_port)


def test_environment_contract_accepts_baseline_and_candidate_only_fields(monkeypatch):
    contract = runpy.run_path(str(REPOSITORY / "deploy/tests/contract.py"))
    configured = contract["configured_environment_variables"]()
    optional = contract["optional_environment_variables"](SYSTEMD)
    assert len(optional) == 41
    assert "STRUGGLEBUS_UPDATER_SOCKET_PATH" in optional
    assert "STRUGGLEBUS_MAINTENANCE_SOCKET_PATH" in optional
    assert "STRUGGLEBUS_UPDATER_REVIEW_TICKETS" in optional
    assert "STRUGGLEBUS_SPN_PACKAGE_TTL_SECONDS" in optional
    assert "STRUGGLEBUS_SPN_MAX_OUTSTANDING_PACKAGES" in optional
    assert "STRUGGLEBUS_SPN_ISSUES_PER_MINUTE" in optional
    for fields in (
        configured - optional - {"STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"},
        configured | optional,
    ):
        monkeypatch.setitem(
            contract["main"].__globals__, "configured_environment_variables",
            lambda: fields,
        )
        assert contract["main"]() == 0


def test_environment_contract_still_rejects_unrendered_fields(monkeypatch):
    contract = runpy.run_path(str(REPOSITORY / "deploy/tests/contract.py"))
    configured = contract["configured_environment_variables"]()
    monkeypatch.setitem(
        contract["main"].__globals__, "configured_environment_variables",
        lambda: configured | {"STRUGGLEBUS_UNRENDERED_SETTING"},
    )
    with pytest.raises(AssertionError, match="systemd/config environment drift"):
        contract["main"]()
