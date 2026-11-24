"""Static security contract for the inert dedicated LAN CA integration."""

from __future__ import annotations

from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
DEPLOY = REPOSITORY / "deploy"


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def main() -> int:
    inventory = (
        DEPLOY / "inventory/example/group_vars/all.yml"
    ).read_text(encoding="utf-8")
    require(
        "strugglebus_domain: bus.lan" in inventory,
        "internal deployment identity must remain bus.lan",
    )
    require(
        "strugglebus_external_domain: bus.u64.lan" in inventory,
        "future canonical identity is missing",
    )
    require(
        "strugglebus_tls_mode: internal" in inventory,
        "tracked TLS mode must remain internal",
    )
    for inert in (
        "strugglebus_lan_ca_stage: false",
        "strugglebus_lan_ca_renewal_enabled: false",
    ):
        require(inert in inventory, f"inert default is missing: {inert}")
    require(
        "strugglebus_lan_ca_activation_evidence_sha256: CHANGE_ME" in inventory,
        "external activation must require immutable evidence",
    )
    require(
        "strugglebus_tls_root: /etc/strugglebus-tls" in inventory,
        "external TLS needs a dedicated Caddy-traversable parent",
    )

    caddy = (
        DEPLOY / "roles/caddy/templates/Caddyfile.j2"
    ).read_text(encoding="utf-8")
    require(
        "{% if strugglebus_tls_mode == 'external' %}" in caddy,
        "external Caddy mode is not explicit",
    )
    require(
        "tls {{ strugglebus_external_cert_path }} "
        "{{ strugglebus_external_key_path }}" in caddy,
        "canonical external certificate paths are missing",
    )
    require(
        caddy.count("Content-Security-Policy") == 1,
        "dual sites must share one hardening snippet",
    )
    require(
        caddy.count("tls internal") >= 2,
        "internal rollback and legacy TLS paths must remain visible",
    )

    tasks = (
        DEPLOY / "roles/lan_ca/tasks/main.yml"
    ).read_text(encoding="utf-8")
    for marker in (
        "strugglebus-lan-ca-activation-v1",
        "server_policy.dns_sans",
        '== ["serverAuth"]',
        "off_machine_restore.verified",
        "checksum_algorithm: sha256",
        "not ansible_check_mode",
        "diff: false",
        "no_log: true",
        "strugglebus-verify-ca-bundle",
        "strugglebus-verify-certificate",
        "strugglebus-cert-renew.timer",
        "group: caddy",
    ):
        require(marker in tasks, f"LAN CA role is missing {marker!r}")
    password_task = tasks[
        tasks.index("- name: Install the protected JWK password")
        : tasks.index("- name: Report protected password staging")
    ]
    for marker in ("no_log: true", "diff: false", "not ansible_check_mode"):
        require(marker in password_task, f"password task is missing {marker!r}")
    require(
        "lookup('env'" not in tasks and "lookup(\"env\"" not in tasks,
        "LAN CA secrets must not use environment lookups",
    )
    require(
        "checksum: \"sha256:" not in tasks,
        "Ansible copy checksum must not misuse a SHA-256 value as SHA-1",
    )

    renew = (
        DEPLOY / "roles/lan_ca/files/strugglebus-renew-certificate.sh"
    ).read_text(encoding="utf-8")
    common = (
        DEPLOY / "roles/lan_ca/files/strugglebus-lan-ca-common.sh"
    ).read_text(encoding="utf-8")
    expiry = (
        DEPLOY
        / "roles/lan_ca/files/strugglebus-check-certificate-expiry.sh"
    ).read_text(encoding="utf-8")
    for forbidden in ("curl -k", "verify=False", "validate_certs: false"):
        require(
            forbidden not in renew + common + tasks,
            f"insecure TLS bypass remains: {forbidden}",
        )
    for marker in (
        "/usr/local/bin/step",
        "/usr/bin/caddy",
        "/usr/bin/systemctl",
        "CREDENTIALS_DIRECTORY",
        "/usr/bin/flock",
        "/usr/bin/mv -Tf",
        "restart_caddy",
        '/usr/bin/timeout 20 "${SYSTEMCTL_BIN}" reload caddy.service',
        '|| "${SYSTEMCTL_BIN}" restart caddy.service',
        "activated.sha256",
        '"status":"rolled-back"',
    ):
        require(marker in renew, f"renewal lifecycle is missing {marker!r}")
    for marker in (
        "certificate must contain exactly the approved DNS SAN",
        "certificate must contain only the serverAuth extended key usage",
        "certificate unexpectedly permits clientAuth",
        "certificate and private key do not match",
        "leaf chain does not contain the expected intermediate",
        "-verify_hostname",
        "-outform DER",
    ):
        require(marker in common, f"certificate validation is missing {marker!r}")
    for marker in (
        "write_status critical",
        "write_unexpected_failure",
        "configuration-unavailable",
        "remaining_seconds",
        "exit 2",
        "exit 1",
        "status.json",
    ):
        require(marker in expiry, f"machine-readable expiry state lacks {marker!r}")

    renew_unit = (
        DEPLOY / "roles/lan_ca/templates/strugglebus-cert-renew.service.j2"
    ).read_text(encoding="utf-8")
    require(
        "LoadCredential=jwk-password:" in renew_unit,
        "renewal secret must use systemd credentials",
    )
    require(
        "ReadWritePaths={{ strugglebus_tls_root }}" in renew_unit,
        "renewal writes must be confined to the TLS root",
    )
    caddy_tasks = (
        DEPLOY / "roles/caddy/tasks/main.yml"
    ).read_text(encoding="utf-8")
    for marker in (
        "Validate external certificate identity before rendering Caddy",
        "Verify Caddy can read but cannot mutate the external private key",
        "'/usr/bin/caddy validate --adapter caddyfile --config %s'",
    ):
        require(marker in caddy_tasks, f"Caddy external preflight lacks {marker!r}")
    require(
        "Disable previously installed LAN CA timers in inert mode" in tasks
        and "- not strugglebus_lan_ca_renewal_enabled | bool" in tasks,
        "inert mode must disable previously installed renewal timers",
    )
    systemd_tasks = (
        DEPLOY / "roles/systemd/tasks/main.yml"
    ).read_text(encoding="utf-8")
    require(
        "notify:\n    - Reload systemd\n    - Restart Strugglebus" in systemd_tasks,
        "application unit changes must restart the running service",
    )

    check_mode = (
        DEPLOY / "tests/lan_ca_check_mode.yml"
    ).read_text(encoding="utf-8")
    require(
        "/usr/bin/mkfifo" in check_mode,
        "check-mode secret non-read test must use a blocking source",
    )
    workflow = (
        REPOSITORY / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    for marker in (
        "lan-ca-integration:",
        "install_lan_ca_test_tools.sh",
        "lan_ca_integration.sh",
        "timeout-minutes: 20",
    ):
        require(marker in workflow, f"mandatory real-CA CI lacks {marker!r}")
    profile_vars = (
        DEPLOY / "roles/deployment_identity/vars/main.yml"
    ).read_text(encoding="utf-8")
    require(
        "default('production')" in profile_vars,
        "an absent deployment profile must resolve to production",
    )
    for reserved in ("bus.lan", "bus.u64.lan", "ca.u64.lan"):
        require(
            reserved in profile_vars,
            f"reserved production identity is missing from the guard: {reserved}",
        )

    profile_tasks = (
        DEPLOY / "roles/deployment_identity/tasks/main.yml"
    ).read_text(encoding="utf-8")
    for marker in (
        'strugglebus_profile in ["production", "development"]',
        'strugglebus_domain == "bus.lan"',
        'strugglebus_external_domain == "bus.u64.lan"',
        "strugglebus_domain not in strugglebus_reserved_domains",
        "strugglebus_external_domain not in strugglebus_reserved_domains",
        "strugglebus_external_domain == strugglebus_domain",
        'and strugglebus_tls_mode == "internal"',
        "strugglebus_validated_profile",
    ):
        require(
            marker in profile_tasks,
            f"deployment identity guard is missing {marker!r}",
        )

    # The guard is only worth having if the roles that carry a TLS identity
    # refuse to run without it, and if it runs before them.
    for name, body in (("caddy", caddy_tasks), ("lan_ca", tasks)):
        require(
            "strugglebus_validated_profile is defined" in body,
            f"{name} must fail closed when the identity guard has not run",
        )
    require(
        'strugglebus_lan_ca_url == "https://ca.u64.lan"' in tasks
        and "not strugglebus_lan_ca_stage | bool" in tasks,
        "development must leave the dedicated LAN CA inert",
    )
    for playbook in ("bootstrap.yml", "configure.yml"):
        body = (DEPLOY / "playbooks" / playbook).read_text(encoding="utf-8")
        require(
            body.index("- role: deployment_identity") < body.index("- role: lan_ca"),
            f"{playbook} must validate the deployment identity first",
        )
    require(
        "strugglebus_deployment_profile: production" in inventory,
        "the tracked deployment profile must remain production",
    )
    consumers = (
        DEPLOY / "tests/deployment_profile_consumers.yml"
    ).read_text(encoding="utf-8")
    for marker in (
        "strugglebus_deployment_profile: development",
        "strugglebus_domain: dev-bus.u64.lan",
        "strugglebus_external_domain: dev-bus.u64.lan",
        "- role: deployment_identity",
        "- role: lan_ca",
    ):
        require(
            marker in consumers,
            f"development consumer test is missing {marker!r}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
