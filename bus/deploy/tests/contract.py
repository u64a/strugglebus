"""Static safety contracts for deployment logic that needs live systemd to run."""

from __future__ import annotations

import ast
import hashlib
import py_compile
import re
from pathlib import Path


DEPLOY_DIR = Path(__file__).resolve().parents[1]
REPOSITORY = DEPLOY_DIR.parent


def require_in_order(content: str, *markers: str) -> None:
    positions = tuple(content.index(marker) for marker in markers)
    if positions != tuple(sorted(positions)):
        raise AssertionError(f"markers are out of order: {markers!r}")


def caddy_key_fingerprint(path: Path) -> str:
    """Return the OpenPGP v4 fingerprint of the first public key in an armored file."""
    import base64

    lines = path.read_text(encoding="ascii").splitlines()
    start = lines.index("") + 1
    body = "".join(line for line in lines[start:] if not line.startswith(("=", "-")))
    data = base64.b64decode(body)
    tag = data[0]
    if tag & 0x40:  # new-format header
        length, offset = (data[1], 2) if data[1] < 192 else (((data[1] - 192) << 8) + data[2] + 192, 3)
    else:
        size = 1 << (tag & 0x03)
        length, offset = int.from_bytes(data[1 : 1 + size], "big"), 1 + size
    packet = data[offset : offset + length]
    if packet[0] != 4:
        raise AssertionError("Caddy package signing key is not an OpenPGP v4 key")
    return hashlib.sha1(  # nosec B324 - OpenPGP v4 fingerprints are defined as SHA-1
        b"\x99" + len(packet).to_bytes(2, "big") + packet, usedforsecurity=False,
    ).hexdigest().upper()


def task_body(content: str, name: str) -> str:
    lines = content.splitlines()
    marker = f"- name: {name}"
    for index, line in enumerate(lines):
        if line.strip() != marker:
            continue
        indentation = len(line) - len(line.lstrip())
        body = []
        for candidate in lines[index + 1 :]:
            if (
                len(candidate) - len(candidate.lstrip()) == indentation
                and candidate.lstrip().startswith("- name:")
            ):
                break
            body.append(candidate)
        return "\n".join(body)
    raise AssertionError(f"task is missing: {name!r}")


def require_isolated_python_argv(path: Path) -> None:
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.strip() not in {
            "- /usr/bin/python3.13",
            '- "{{ strugglebus_release_python_interpreter_path }}"',
        }:
            continue
        if index + 1 >= len(lines) or lines[index + 1].strip() != "- -I":
            raise AssertionError(
                f"{path.name} omits -I after the pinned Python interpreter"
            )


def configured_environment_variables() -> set[str]:
    source = (REPOSITORY / "src/strugglebus/config.py").read_text()
    tree = ast.parse(source)
    variables = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.fullmatch(r"STRUGGLEBUS_[A-Z][A-Z0-9_]+", node.value)
    }
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id in {
                "RECONNECT_SETTING_LIMITS", "OPERATOR_SETTING_BOUNDS",
                "UPDATER_SETTING_BOUNDS",
            }
            for target in node.targets
        ):
            values = ast.literal_eval(node.value)
            if not isinstance(values, dict) or any(
                not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]+", name)
                for name in values
            ):
                raise AssertionError("invalid bounded configuration contract")
            variables.update("STRUGGLEBUS_" + name.upper() for name in values)
    return variables


def optional_environment_variables(unit: str) -> set[str]:
    loops = re.findall(
        r"{% for setting in (\[[^\n]+\]) %}\n"
        r"{% if \('strugglebus_' ~ setting\) in vars %}\n"
        r"Environment=STRUGGLEBUS_{{ setting \| upper }}={{ vars\['strugglebus_' ~ setting\] }}\n"
        r"{% endif %}\n{% endfor %}",
        unit,
    )
    if not loops or len(loops) != unit.count("{% for setting in "):
        raise AssertionError("candidate-only settings must remain explicitly opt-in")
    names = []
    for loop in loops:
        parsed = ast.literal_eval(loop)
        if not isinstance(parsed, list):
            raise AssertionError("invalid candidate-only environment rendering")
        names.extend(parsed)
    if (
        any(not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]+", name)
               for name in names)
        or len(names) != len(set(names))
        or "Environment=STRUGGLEBUS_{{ setting | upper }}={{ vars['strugglebus_' ~ setting] }}"
        not in unit
    ):
        raise AssertionError("invalid candidate-only environment rendering")
    return {"STRUGGLEBUS_" + name.upper() for name in names}


def require_helper_checksum_declarations() -> None:
    validator_tree = ast.parse((DEPLOY_DIR / "validate.py").read_text())
    validator_checksums = None
    for node in ast.walk(validator_tree):
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "expected_sha256"
                for target in node.targets
            )
        ):
            validator_checksums = ast.literal_eval(node.value)
            break
    if validator_checksums is None:
        raise AssertionError("deploy validator omits helper checksum declarations")

    runtime_checksums = {}
    for relative_path in (
        "roles/guest_base/tasks/main.yml",
        "roles/systemd/tasks/main.yml",
        "roles/release/tasks/maintenance_configuration.yml",
    ):
        tasks = (DEPLOY_DIR / relative_path).read_text()
        for match in re.finditer(
            r"source:\s+[^\n]*/(?P<name>[^/\"\s]+)\"?"
            r"(?:(?!\n\s*-\s+(?:source|name):).)*?"
            r"\n\s+sha256:\s+(?P<sha256>[0-9a-f]{64})",
            tasks,
            re.DOTALL,
        ):
            name, checksum = match.group("name"), match.group("sha256")
            if name in runtime_checksums and runtime_checksums[name] != checksum:
                raise AssertionError(f"runtime checksums disagree for {name}")
            runtime_checksums[name] = checksum

    helper_paths = {
        path.name: path
        for directory in (
            DEPLOY_DIR / "roles/guest_base/files",
            DEPLOY_DIR / "files",
            DEPLOY_DIR / "roles/systemd/templates",
        )
        for path in directory.iterdir()
        if path.name in validator_checksums
    }
    if set(helper_paths) != set(validator_checksums):
        raise AssertionError("validator helper checksum set does not match helper files")
    if set(runtime_checksums) != set(validator_checksums):
        raise AssertionError("runtime and validator helper checksum sets differ")

    for name, path in helper_paths.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if runtime_checksums[name] != actual:
            raise AssertionError(f"runtime checksum for {name} does not match its source")
        if validator_checksums[name] != actual:
            raise AssertionError(f"validator checksum for {name} does not match its source")


def main() -> int:
    require_helper_checksum_declarations()
    release_materialize = (
        DEPLOY_DIR / "roles/release/tasks/materialize_release.yml"
    ).read_text()
    release_initial_install = (
        DEPLOY_DIR / "roles/release/tasks/initial_install.yml"
    ).read_text()
    release_main = (DEPLOY_DIR / "roles/release/tasks/main.yml").read_text()
    guest_base = (DEPLOY_DIR / "roles/guest_base/tasks/main.yml").read_text()
    systemd = "\n".join(
        (
            (DEPLOY_DIR / "roles/systemd/tasks/main.yml").read_text(),
            (DEPLOY_DIR / "roles/systemd/tasks/backup_timer.yml").read_text(),
        )
    )
    backup_unit = (
        DEPLOY_DIR / "roles/systemd/templates/strugglebus-backup.service.j2"
    ).read_text()
    attributes = (REPOSITORY / ".gitattributes").read_text()
    release_validation = (
        DEPLOY_DIR / "roles/release/tasks/validate.yml"
    ).read_text()
    immutable_preflight = (
        DEPLOY_DIR / "roles/release/tasks/immutable_preflight.yml"
    ).read_text()
    require_in_order(
        release_materialize,
        "- name: Renew the release locks before artifact mutation",
        "- name: Create the immutable release directory",
        "- name: Renew the release locks before dependency installation",
        "- name: Renew the release locks before application installation",
        "- name: Renew the release locks before recording installed metadata",
        "- name: Mark the immutable release installed",
    )
    require_in_order(
        release_initial_install,
        "- name: Require a blank or exact idempotent first-install state",
        "- name: Require exact controller release artifact checksums",
        "- name: Validate the first-install hash-locked dependency artifact",
        "- name: Verify immutable first-install release state",
        "- name: Materialize the exact first immutable release",
        "- name: Validate the complete first immutable release",
        "- name: Activate and verify the first managed release",
        "    - name: Activate the first release atomically",
        "    - name: Require TLS-verified readiness from the first managed release",
        "  rescue:",
        "    - name: Stop an unverified first release",
        "    - name: Remove the failed first-release staging link",
        "    - name: Remove the failed first-release selection",
        "    - name: Remove mutable state created only by the failed first start",
        "    - name: Refuse an unverified first-release activation",
    )
    for forbidden in (
        "strugglebus_cutover_operation_id",
        "strugglebus_cutover_prestage_sha256",
        "previous release",
    ):
        if forbidden in release_initial_install:
            raise AssertionError(
                f"first install must not pretend cutover state exists: {forbidden!r}"
            )
    require_in_order(
        immutable_preflight,
        "- name: Find existing wheel artifacts in the versioned release",
        "- name: Refuse to mutate a versioned release",
        "- name: Refuse a changed wheel basename in a versioned release",
        "- name: Refuse inconsistent installed release metadata",
    )
    if "file_type: any" not in immutable_preflight:
        raise AssertionError("immutable preflight does not inspect every wheel entry")
    require_in_order(
        release_main,
        "- name: Select the fixed release helper interpreter",
        "- name: Inspect the production Python interpreter",
        "- name: Require the protected production Python interpreter",
        "- name: Inspect release safety runtime helpers",
        "- name: Require the configured release safety runtime",
        "- name: Import release safety helpers in isolated mode",
        "- name: Import the backup helper through the service-user boundary",
        "- name: Run release action under the exclusive lock",
        "  block:",
        "    - name: Acquire the bounded process-owned release lock",
        "  always:",
        "    - name: Release the access-freeze transition lock",
        "    - name: Release the process-owned release lock",
        "- name: Validate the release action without acquiring a lock in check mode",
    )
    for marker in (
        "/usr/local/libexec/strugglebus-release-lock",
        "/usr/local/libexec/strugglebus-validate-release",
        "/usr/local/libexec/strugglebus-validate-backup",
        "/usr/local/libexec/strugglebus-inspect-access-freeze",
        "/usr/local/libexec/strugglebus-sqlite-backup",
        "/var/lib/strugglebus-release-staging",
        "/run/lock/strugglebus/release.lock",
        "/run/lock/strugglebus/release.json",
        "strugglebus_release_lock_wait_seconds | default(30)",
        "strugglebus_release_lock_lease_seconds | default(7200)",
    ):
        if marker not in release_main:
            raise AssertionError(f"process-owned release lock is missing {marker!r}")
    for content, label in (
        (guest_base, "guest-base"),
        (release_main, "release"),
    ):
        for marker in (
            "/usr/bin/python3.13",
            "stat.isreg",
            "stat.islnk",
            "stat.executable",
            'stat.pw_name | default("") == "root"',
            'stat.gr_name | default("") == "root"',
            "stat.wgrp",
            "stat.woth",
        ):
            if marker not in content:
                raise AssertionError(
                    f"{label} Python interpreter validation is missing {marker!r}"
                )
    for marker in (
        "/usr/bin/timeout",
        "/usr/sbin/runuser",
        "/usr/bin/env",
        "/usr/bin/python3.13",
    ):
        if marker not in systemd:
            raise AssertionError(
                f"configure-time service helper probe is missing {marker!r}"
            )
    if (
        "ExecStart=/usr/bin/python3.13 -I "
        "/usr/local/libexec/strugglebus-sqlite-backup"
    ) not in backup_unit:
        raise AssertionError("backup service does not use the pinned isolated interpreter")
    for pattern in ("*.bash", "*.j2", "*.py", "*.sh"):
        if f"{pattern} text eol=lf" not in attributes:
            raise AssertionError(f"repository LF policy is missing {pattern!r}")
    for path in (
        DEPLOY_DIR / "roles/guest_base/tasks/main.yml",
        DEPLOY_DIR / "roles/release/tasks/main.yml",
        DEPLOY_DIR / "roles/release/tasks/renew_lock.yml",
        DEPLOY_DIR / "roles/systemd/tasks/main.yml",
    ):
        content = path.read_text()
        if "/usr/bin/python3\n" in content:
            raise AssertionError(f"{path.name} uses the unpinned production interpreter")
        require_isolated_python_argv(path)
    for marker in (
        "strugglebus_release_test_python_interpreter",
        'else "/usr/bin/python3.13"',
        'path: "{{ strugglebus_release_python_interpreter_path }}"',
        '- "{{ strugglebus_release_python_interpreter_path }}"',
    ):
        if marker not in release_main:
            raise AssertionError(
                f"release interpreter selection is missing {marker!r}"
            )
    for content, label in (
        (guest_base, "guest-base"),
        (release_main, "release"),
    ):
        for marker in (
            "/usr/sbin/runuser",
            "stat.isreg",
            "stat.islnk",
            "stat.executable",
            'stat.pw_name | default("") == "root"',
            'stat.gr_name | default("") == "root"',
            "stat.wgrp",
            "stat.woth",
        ):
            if marker not in content:
                raise AssertionError(
                    f"{label} runuser validation is missing {marker!r}"
                )
    if "      - util-linux" not in guest_base:
        raise AssertionError("guest-base does not guarantee util-linux")
    for marker in (
        "strugglebus_owner_accepts_missing_weekly_vzdump_risk",
        "!=",
        "weekly snapshot-mode zstd job",
        "keep-last=4",
    ):
        if marker not in release_validation:
            raise AssertionError(
                f"release backup-policy gate is missing {marker!r}"
            )
    require_in_order(
        release_validation,
        "(strugglebus_assert_external_vzdump | default(false)) is boolean",
        "strugglebus_owner_accepts_missing_weekly_vzdump_risk\n"
        "          | default(false)\n"
        "        ) is boolean",
        "        !=",
    )
    for flag in (
        "strugglebus_assert_external_vzdump",
        "strugglebus_owner_accepts_missing_weekly_vzdump_risk",
    ):
        if f"{flag} | default(false) | bool" in release_validation:
            raise AssertionError(
                f"release governance flag is coercively converted: {flag}"
            )
    if "application.whl" in release_materialize:
        raise AssertionError("release renames the wheel to an invalid filename")
    if release_materialize.count("strugglebus_wheel_src | basename") != 3:
        raise AssertionError(
            "release does not preserve the validated wheel basename throughout"
        )
    readiness_tasks = (
        (
            release_initial_install,
            "Require TLS-verified readiness from the first managed release",
        ),
    )
    for content, name in readiness_tasks:
        body = task_body(content, name)
        if 'ca_path: "{{ strugglebus_caddy_ca_path }}"' not in body:
            raise AssertionError(f"{name!r} omits the configured internal CA path")
        if re.search(r"validate_certs:\s*(?:false|no|0)\b", body, re.IGNORECASE):
            raise AssertionError(f"{name!r} disables TLS certificate validation")
    release_check_mode = (
        DEPLOY_DIR / "tests/release_check_mode.yml"
    ).read_text()
    if (
        "roles:\n    - role: release" not in release_check_mode
        or "tasks_from:" in release_check_mode
    ):
        raise AssertionError("check-mode regression bypasses the release role entrypoint")

    proxmox = (DEPLOY_DIR / "roles/proxmox_lxc/tasks/main.yml").read_text()
    require_in_order(
        proxmox,
        "import_tasks: validate.yml",
        "include_tasks: api.yml",
    )
    proxmox_api = (
        DEPLOY_DIR / "roles/proxmox_lxc/tasks/api.yml"
    ).read_text()
    if (
        'pubkey: "{{ strugglebus_effective_ssh_public_key }}"'
        not in proxmox_api
    ):
        raise AssertionError("LXC creation does not inject the validated SSH key")
    require_in_order(
        proxmox_api,
        "community.proxmox.proxmox_vm_info:",
        "community.proxmox.proxmox:",
    )
    proxmox_validation = (
        DEPLOY_DIR / "roles/proxmox_lxc/tasks/validate.yml"
    ).read_text()
    require_in_order(
        proxmox_validation,
        "- name: Validate the API-token backend inputs",
        "- name: Validate the OpenSSH public key prefix",
        "- name: Validate the complete OpenSSH public key wire format",
        "        | strugglebus_public_key_errors",
    )
    if proxmox_validation.count("proxmox_api_token_secret") != 1:
        raise AssertionError("API secret escaped its API-only validation boundary")

    unit = (
        DEPLOY_DIR / "roles/systemd/templates/strugglebus.service.j2"
    ).read_text()
    configured = configured_environment_variables()
    release_environment = {"STRUGGLEBUS_RELEASE_ID"}
    optional = optional_environment_variables(unit)
    rendered = set(
        re.findall(r"^Environment=(STRUGGLEBUS_[A-Z0-9_]+)=", unit, re.MULTILINE)
    )
    if optional & (rendered | release_environment):
        raise AssertionError("candidate-only settings duplicate unconditional configuration")
    operator_projection = (
        "{% if strugglebus_operator_password_source | default('') | length > 0 %}\n"
        "LoadCredential=operator-password:{{ strugglebus_operator_password_source }}\n"
        "Environment=STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH=%d/operator-password\n"
        "{% endif %}"
    )
    if operator_projection not in unit:
        raise AssertionError("operator projection must remain an exact optional guest-side reference")
    rendered -= {"STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"} - configured
    rendered |= optional & configured
    if rendered != configured - release_environment:
        raise AssertionError(
            "systemd/config environment drift: "
            f"missing={sorted(configured - release_environment - rendered)!r}, "
            f"extra={sorted(rendered - configured)!r}"
        )
    for marker in (
        "EnvironmentFile=-{{ strugglebus_current_link }}/release.env",
        "STRUGGLEBUS_RELEASE_ID={{ strugglebus_release_version }}",
        "- name: Record the immutable runtime release identifier",
        "--require-release-id",
    ):
        if marker not in (
            unit + release_materialize + release_initial_install
        ):
            raise AssertionError(
                f"runtime release identity wiring is missing {marker!r}"
            )
    if "STRUGGLEBUS_ADMIN_TOKEN_FILE" in unit:
        raise AssertionError("obsolete admin credential variable remains")
    if "venv/bin/strugglebus serve" not in unit:
        raise AssertionError("systemd must use the shutdown-aware service entry point")
    cli = (REPOSITORY / "src/strugglebus/cli.py").read_text(encoding="utf-8")
    for setting in ("access_log=False", "proxy_headers=False", "server_header=False"):
        if setting not in cli:
            raise AssertionError(f"Uvicorn safety setting is missing: {setting!r}")

    inventory = (
        DEPLOY_DIR / "inventory/example/group_vars/all.yml"
    ).read_text()
    inventory_variables = set(
        re.findall(r"^(strugglebus_[a-z0-9_]+):", inventory, re.MULTILINE)
    )
    inventory_aliases = {
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": "strugglebus_admin_token_src",
        "STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH": "strugglebus_operator_password_source",
        "STRUGGLEBUS_SATELLITE_CA_KEY_PATH": "strugglebus_satellite_hostname",
        "STRUGGLEBUS_SATELLITE_GATEWAY_WG_ADDRESS": "strugglebus_satellite_hostname",
        "STRUGGLEBUS_ALLOWED_HOSTS": "strugglebus_domain",
        "STRUGGLEBUS_ALLOWED_ORIGINS": "strugglebus_domain",
        "STRUGGLEBUS_CA_BUNDLE_PATH": "strugglebus_lan_ca_published_root_path",
        "STRUGGLEBUS_CA_ROOT_SHA256": "strugglebus_lan_ca_root_sha256",
        "STRUGGLEBUS_PUBLIC_BASE_URL": "strugglebus_domain",
    }
    template_defaulted = {
        "STRUGGLEBUS_ROE_ENFORCEMENT_MODE",
        "STRUGGLEBUS_MAX_ACTIVE_CREDENTIALS_PER_AGENT",
        "STRUGGLEBUS_MAX_PENDING_CREDENTIALS_PER_AGENT",
        "STRUGGLEBUS_CREDENTIAL_PENDING_SECONDS",
        "STRUGGLEBUS_SELF_ROTATIONS_PER_WINDOW",
        "STRUGGLEBUS_SELF_ROTATION_WINDOW_SECONDS",
        "STRUGGLEBUS_ENROLLMENT_TTL_SECONDS",
        "STRUGGLEBUS_MAX_ENROLLMENT_USES",
    }
    if (
        "{{ strugglebus_roe_enforcement_mode | default('observe') }}"
        not in unit
    ):
        raise AssertionError("RoE enforcement must retain its safe deployment default")
    for default in (
        "{{ strugglebus_enrollment_ttl_seconds | default(900) }}",
        "{{ strugglebus_max_enrollment_uses | default(1) }}",
    ):
        if default not in unit:
            raise AssertionError(
                "agent enrollment must retain its short-lived single-use default"
            )
    expected_inventory = {
        inventory_aliases.get(variable, variable.lower())
        for variable in configured - release_environment - template_defaulted - optional
    }
    missing_inventory = expected_inventory - inventory_variables
    if missing_inventory:
        raise AssertionError(
            f"example inventory is missing config variables: {sorted(missing_inventory)!r}"
        )
    render_validation = (DEPLOY_DIR / "tests/render.yml").read_text()
    for variable in optional:
        if (
            variable.lower() in inventory_variables
            or f"# {variable.lower()}:" not in inventory
            or variable not in render_validation
        ):
            raise AssertionError(f"candidate-only setting lacks opt-in inventory/render coverage: {variable}")
    if (
        "vars_files:\n    - ../inventory/example/group_vars/all.yml"
        not in render_validation
    ):
        raise AssertionError(
            "offline rendering must derive configuration from example inventory"
        )
    if re.search(r"^\s+strugglebus_domain:", render_validation, re.MULTILINE):
        raise AssertionError("offline rendering duplicates the deployment domain")

    deployment_documentation = (
        REPOSITORY / "docs/DEPLOYMENT.md"
    ).read_text()
    hard_stop_steps = (
        "**Stop exposure first:**",
        "**Preserve evidence before repair:**",
        "Recover only onto an immutable release",
        "**Restore exposure last:**",
    )
    hard_stop_positions = tuple(
        deployment_documentation.index(step) for step in hard_stop_steps
    )
    if hard_stop_positions != tuple(sorted(hard_stop_positions)):
        raise AssertionError(
            "hard-stop recovery must stop exposure, preserve evidence, recover, "
            "then restore exposure"
        )
    for required_freeze_contract in (
        "agent_access_freeze=global-v1",
        "A pre-freeze backup is not an ordinary rollback path",
        "Verify Caddy HTTPS and application loopback listeners are absent",
    ):
        if required_freeze_contract not in deployment_documentation:
            raise AssertionError(
                "access-freeze recovery contract is missing: "
                f"{required_freeze_contract!r}"
            )
    access_source = (REPOSITORY / "src/strugglebus/access.py").read_text()
    release_main = (
        DEPLOY_DIR / "roles/release/tasks/main.yml"
    ).read_text()
    shared_transition_lock = ".access-freeze-lock/transition.lock"
    if (
        "ACCESS_FREEZE_LOCK_DIRECTORY = \".access-freeze-lock\""
        not in access_source
        or shared_transition_lock not in release_main
        or "Acquire the access-freeze transition lock as the service identity"
        not in release_main
        or "Release the access-freeze transition lock" not in release_main
    ):
        raise AssertionError(
            "operator transitions and release mutations must share the persistent lock"
        )
    updater_documentation = (REPOSITORY / "docs/UPDATER_BOOTSTRAP.md").read_text()
    undocumented = configured - {
        variable
        for variable in configured
        if variable in deployment_documentation or variable in updater_documentation
    }
    if undocumented:
        raise AssertionError(
            f"deployment config variables are undocumented: {sorted(undocumented)!r}"
        )

    caddy = (
        DEPLOY_DIR / "roles/caddy/templates/Caddyfile.j2"
    ).read_text()
    expected_caddy_csp = (
        "default-src 'none'; style-src 'self'; script-src 'none'; "
        "connect-src 'none'; img-src 'none'; font-src 'none'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    for directive in (
        "auto_https disable_redirects",
        "tls internal",
        "header_up Host {host}",
        "flush_interval -1",
        "reverse_proxy {{ strugglebus_bind_host }}:{{ strugglebus_bind_port }}",
    ):
        if directive not in caddy:
            raise AssertionError(f"Caddy safety directive is missing: {directive!r}")
    if (
        "strugglebus_external_tls_legacy_compatibility_site | default(true)"
        not in caddy
    ):
        raise AssertionError("external TLS compatibility must retain its safe default")
    caddy_csp_matches = re.findall(
        r'Content-Security-Policy "([^"]+)"',
        caddy,
    )
    if caddy_csp_matches != [expected_caddy_csp]:
        raise AssertionError("Caddy must enforce the exact strict console CSP")
    if re.findall(r'^\s*(\S*Referrer-Policy)\s+"([^"]+)"', caddy, re.MULTILINE) != [
        ("?Referrer-Policy", "no-referrer"),
    ]:
        raise AssertionError("Caddy must default, not override, the upstream referrer policy")
    any_ipv4 = ".".join(("0", "0", "0", "0"))
    if any_ipv4 in caddy or "[::]" in caddy:
        raise AssertionError("Caddy must proxy only to the configured loopback bind")
    caddy_runtime = (
        DEPLOY_DIR / "roles/caddy/templates/strugglebus-runtime.conf.j2"
    ).read_text()
    for directive in (
        "RuntimeDirectory=caddy",
        "RuntimeDirectoryMode=0750",
        "UMask=0077",
    ):
        if directive not in caddy_runtime:
            raise AssertionError(
                f"Caddy runtime safety directive is missing: {directive!r}"
            )
    caddy_tasks = (DEPLOY_DIR / "roles/caddy/tasks/main.yml").read_text()
    for marker in (
        "(strugglebus_external_tls_legacy_compatibility_site | default(true))",
        'strugglebus_tls_mode == "external"',
    ):
        if marker not in caddy_tasks:
            raise AssertionError(
                f"Caddy compatibility validation is missing {marker!r}"
            )
    caddy_activation_plan = (
        DEPLOY_DIR / "roles/caddy/tasks/activation_plan.yml"
    ).read_text()
    caddy_apply = (DEPLOY_DIR / "roles/caddy/tasks/apply.yml").read_text()
    caddy_check_mode = (
        DEPLOY_DIR / "tests/caddy_check_mode.yml"
    ).read_text()
    caddy_activation_order = (
        DEPLOY_DIR / "tests/caddy_activation_order.yml"
    ).read_text()
    caddy_activation_plan_test = (
        DEPLOY_DIR / "tests/caddy_activation_plan.yml"
    ).read_text()
    caddy_verification = (
        DEPLOY_DIR / "roles/caddy/tasks/verify.yml"
    ).read_text()
    require_in_order(
        caddy_tasks,
        "- name: Reject the internal Caddy activation test fixture",
        "- name: Install Caddy",
        "- name: Create the Caddy systemd override directory",
        "- name: Install the private Caddy runtime directory policy",
        "  register: caddy_runtime_policy_result",
        "- name: Install the LAN-only Caddy configuration",
        "  register: caddy_config_result",
        "- name: Inspect the managed Caddy runtime policy",
        "- name: Inspect the managed Caddy configuration",
        "- name: Require regular managed Caddy files",
        "- name: Inspect the verified Caddy activation marker",
        "- name: Require a protected Caddy activation marker",
        "- name: Read the verified Caddy activation marker",
        "- name: Inspect the loaded Caddy systemd state",
        "- name: Derive the explicit Caddy activation plan",
        "- name: Apply the validated Caddy activation plan before enablement",
        "  ansible.builtin.include_tasks: apply.yml",
        "- name: Report Caddy activation predicted by check mode",
        "- name: Enable Caddy after validated activation",
        "- name: Report Caddy enablement predicted by check mode",
        "- name: Require Caddy runtime safety after activation planning",
        "  ansible.builtin.include_tasks: verify.yml",
    )
    caddy_package = (DEPLOY_DIR / "roles/caddy/tasks/package.yml").read_text()
    for marker in (
        "signed_by: /etc/apt/keyrings/caddy-stable.asc",
        "uris: https://dl.cloudsmith.io/public/caddy/stable/deb/debian",
        "    policy_rc_d: 101",
        "#clear Unattended-Upgrade::Origins-Pattern;",
        '"origin=cloudsmith/caddy/stable";',
        '"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";',
    ):
        if marker not in caddy_package:
            raise AssertionError(f"Caddy package task is missing {marker!r}")
    if caddy_key_fingerprint(DEPLOY_DIR / "roles/caddy/files/caddy-stable.asc") != (
        "65760C51EDEA2017CEA2CA15155B6D79CA56EA34"
    ):
        raise AssertionError("Caddy package signing key is not the reviewed key")
    for marker in (
        "caddy_activation_test_fixture is not defined",
        "default('/etc/systemd/system/caddy.service.d')",
        "+ '/strugglebus-runtime.conf'",
        "      - --property=ActiveState",
        "      - --property=SubState",
        "      - --property=UnitFileState",
        "      - --property=DropInPaths",
        "  check_mode: false",
    ):
        if marker not in caddy_tasks:
            raise AssertionError(f"Caddy runtime task is missing {marker!r}")
    for forbidden in ("notify:", "flush_handlers", "state: started"):
        if forbidden in caddy_tasks:
            raise AssertionError(
                f"Caddy activation retains fragile behavior: {forbidden!r}"
            )
    for marker in (
        "- name: Exercise stopped Caddy configuration in check mode",
        "caddy_manage_package: false",
        "- role: caddy",
        "- name: Require zero Caddy check-mode mutation",
    ):
        if marker not in caddy_check_mode:
            raise AssertionError(
                f"Caddy check-mode scenario is missing {marker!r}"
            )
    require_in_order(
        caddy_activation_plan,
        "- name: Validate the Caddy systemd state response",
        "- name: Parse the Caddy systemd state",
        "- name: Record the Caddy activation requirements",
    )
    for marker in (
        "caddy_runtime_policy_result.changed | bool",
        "caddy_config_result.changed | bool",
        "caddy_loaded_active_state != 'active'",
        "caddy_loaded_sub_state != 'running'",
        ") not in caddy_loaded_dropin_paths",
        "not caddy_activation_marker_file.stat.exists",
        "caddy_activation_marker_read.content",
        "caddy_loaded_unit_file_state != 'enabled'",
    ):
        if marker not in caddy_activation_plan:
            raise AssertionError(
                f"Caddy activation planning is missing {marker!r}"
            )
    require_in_order(
        caddy_apply,
        "- name: Validate Caddy configuration",
        "      - caddy",
        "      - validate",
        "    - name: Stop Caddy after failed validation",
        "    - name: Report failed Caddy validation",
        "- name: Reload systemd and restart Caddy",
        "    daemon_reload: true",
        "    state: restarted",
        "- name: Stop Caddy after failed restart",
        "- name: Report failed Caddy restart",
        "- name: Verify Caddy runtime after restart",
        "  ansible.builtin.include_tasks: verify.yml",
        "- name: Record the verified Caddy activation fingerprints",
    )
    for marker in (
        "- name: Exercise sequential Caddy activation outcomes",
        "package-default-stopped",
        "ansible.builtin.include_tasks: ../roles/caddy/tasks/apply.yml",
        "- name: Record enablement only after verified activation",
        "- name: Verify the healthy unchanged fixture without reactivation",
        "ansible.builtin.include_tasks: ../roles/caddy/tasks/verify.yml",
    ):
        if marker not in caddy_activation_order:
            raise AssertionError(
                f"Caddy executable activation scenario is missing {marker!r}"
            )
    for marker, content in (
        ('write("validate\\n")', caddy_apply),
        ('write("restart\\n")', caddy_apply),
        ('event="verify" if current == "restarted"', caddy_verification),
        ('write("stop\\n")', caddy_verification),
    ):
        if marker not in content:
            raise AssertionError(
                f"Caddy injectable production action is missing {marker!r}"
            )
    for marker in (
        "name: fresh-install",
        "name: exact-partial-recovery",
        "name: changed-config",
        "name: unapplied-config",
        "name: healthy-unchanged",
        "include_tasks: tasks/caddy_activation_plan_case.yml",
    ):
        if marker not in caddy_activation_plan_test:
            raise AssertionError(
                f"Caddy activation-plan scenario is missing {marker!r}"
            )
    require_in_order(
        caddy_verification,
        "- name: Inspect the private Caddy runtime directory",
        "- name: Inspect the private Caddy admin socket",
        "- name: Verify Caddy is active after restart",
        "- name: Inspect Caddy TCP listeners",
        "- name: Normalize the Caddy runtime observation",
        "- name: Record the named Caddy runtime checks",
        "- name: Retain the failed Caddy runtime predicates",
        "- name: Build the sanitized Caddy failure report",
        "- name: Stop Caddy after failed runtime verification",
        "- name: Require the protected Caddy runtime and HTTPS-only listener",
    )
    for marker in (
        "caddy_runtime_directory.stat.mode | default('') == '0750'",
        "caddy_admin_socket.stat.mode | default('') in ['0200', '0700']",
        "caddy_normalized_listener_addresses",
        "failed_predicates:",
        "runtime_directory:",
        "admin_socket:",
        "systemctl_active:",
        "tcp_listener_addresses:",
    ):
        if marker not in caddy_verification:
            raise AssertionError(f"Caddy verification is missing {marker!r}")
    for predicate in (
        "runtime_dir_exists",
        "runtime_dir_type",
        "runtime_dir_owner",
        "runtime_dir_group",
        "runtime_dir_mode",
        "runtime_dir_not_symlink",
        "admin_socket_exists",
        "admin_socket_type",
        "admin_socket_owner",
        "admin_socket_group",
        "admin_socket_mode",
        "admin_socket_not_symlink",
        "systemctl_active",
        "listener_probe_succeeded",
        "https_listener_present",
        "http_listener_absent",
    ):
        if f"{predicate}:" not in caddy_verification:
            raise AssertionError(
                f"Caddy verification omits named predicate {predicate!r}"
            )
        if predicate not in caddy_activation_order:
            raise AssertionError(
                f"Caddy executable attribution omits {predicate!r}"
            )
    for forbidden in ("journalctl", "environ", "cmdline", "certificate"):
        if forbidden in caddy_verification.lower():
            raise AssertionError(
                f"Caddy failure report includes forbidden field {forbidden!r}"
            )
    if caddy_apply.count("when: not ansible_check_mode") < 2:
        raise AssertionError("Caddy check mode may restart or verify the service")

    backup_unit = (
        DEPLOY_DIR / "roles/systemd/templates/strugglebus-backup.service.j2"
    ).read_text()
    if f"ReadOnlyPaths={{{{ strugglebus_data_dir }}}}" in backup_unit:
        raise AssertionError("WAL source directory is mounted read-only")

    ci_workflow = (REPOSITORY / ".github/workflows/ci.yml").read_text()
    fork_guard = (
        "github.event_name != 'pull_request' || "
        "github.event.pull_request.head.repo.full_name == github.repository"
    )
    ci_lines = ci_workflow.splitlines()
    jobs_start = ci_lines.index("jobs:") + 1
    job_starts = [
        (index, match.group(1))
        for index, line in enumerate(ci_lines[jobs_start:], start=jobs_start)
        if (match := re.fullmatch(r"  ([A-Za-z_][A-Za-z0-9_-]*):", line))
    ]
    job_blocks = {
        name: "\n".join(
            ci_lines[
                start : (
                    job_starts[offset + 1][0]
                    if offset + 1 < len(job_starts)
                    else len(ci_lines)
                )
            ]
        )
        for offset, (start, name) in enumerate(job_starts)
    }
    prox_runner_jobs = {
        name: block
        for name, block in job_blocks.items()
        if "self-hosted" in block or "prox-runner" in block
    }
    if not prox_runner_jobs:
        raise AssertionError("CI must retain protected prox-runner jobs")
    if any(block.count("\n    runs-on:") != 1 for block in job_blocks.values()):
        raise AssertionError("each CI job must declare exactly one runner")
    full_gate_scope = (
        "github.event_name == 'workflow_dispatch' || "
        "github.ref == 'refs/heads/main' || github.base_ref == 'main'"
    )
    full_gate_jobs = {"deployment", "lan-ca-integration"}
    for name, block in prox_runner_jobs.items():
        guard = (
            f"    if: ({fork_guard}) && ({full_gate_scope})"
            if name in full_gate_jobs
            else f"    if: {fork_guard}"
        )
        if guard not in block.splitlines():
            raise AssertionError(
                f"prox-runner job {name!r} does not reject fork code"
            )
    if "  push:\n    branches: [main, develop]\n" not in ci_workflow:
        raise AssertionError("CI must run on pushes to main and develop")

    fork_policy = (
        REPOSITORY / ".github/workflows/fork-policy.yml"
    ).read_text()
    expected_fork_policy = """name: Fork policy

on:
  pull_request_target: # zizmor: ignore[dangerous-triggers] base-only static policy; no head code
    types: [opened, reopened, synchronize]

permissions: {}

jobs:
  fork-policy:
    name: Fork policy
    runs-on: [self-hosted, prox-runner]
    timeout-minutes: 1
    defaults:
      run:
        shell: bash
    steps:
      - name: Reject fork-originated pull requests
        if: github.event.pull_request.head.repo.full_name != github.repository
        run: |
          echo "::error::Fork-originated pull requests cannot run repository CI."
          exit 1

      - name: Accept same-repository pull requests
        if: github.event.pull_request.head.repo.full_name == github.repository
        run: echo "Same-repository pull request is eligible for protected CI."
"""
    if fork_policy != expected_fork_policy:
        raise AssertionError(
            "fork policy must remain the reviewed base-only static workflow"
        )

    security_documentation = (
        REPOSITORY / "docs/SECURITY_TESTING.md"
    ).read_text()
    for governance_marker in (
        "branch-protection and ruleset APIs return `403`",
        "Manual governance therefore requires",
        "same-repository validation pull request",
        "A plan upgrade is optional",
    ):
        if governance_marker not in security_documentation:
            raise AssertionError(
                "manual fork governance is missing "
                f"{governance_marker!r}"
            )
    if "configure the `main` branch ruleset or branch protection" in (
        security_documentation
    ):
        raise AssertionError(
            "documentation claims unavailable native required checks"
        )

    helper_bootstrap = (
        DEPLOY_DIR / "roles/guest_base/tasks/validated_python_helper.yml"
    ).read_text()
    require_in_order(
        helper_bootstrap,
        "- name: Require the exact reviewed Python helper source",
        "- name: Import and verify the reviewed Python helper contract",
        "- name: Verify the reviewed access-freeze inspector behavior",
        'ansible.builtin.copy:',
        "- name: Require the exact installed Python helper",
        "- name: Import the installed Python helper in isolated mode",
    )
    for marker in (
        "checksum_algorithm: sha256",
        "strugglebus_python_helper_source.stat.checksum",
        "strugglebus_python_helper_source.stat.nlink",
        "strugglebus_python_helper_destination.stat.checksum",
        "strugglebus_python_helper_destination.stat.nlink",
        "not ansible_check_mode",
        "strugglebus_python_helper_copy.changed",
        "destination_command_prefix",
        "check_mode: false",
    ):
        if marker not in helper_bootstrap:
            raise AssertionError(
                f"helper check-mode bootstrap is missing {marker!r}"
            )
    for marker in ("validated_python_helper.yml",):
        if marker not in guest_base:
            raise AssertionError(
                f"guest-base helper binding is missing {marker!r}"
            )
    for marker in (
        "validated_python_helper.yml",
        "88f3d71550b147b3cdb26c201b5e60bd156d914a68687e75bb3d6cb85c4dd5b3",
        "Install the SQLite backup program",
    ):
        if marker not in systemd:
            raise AssertionError(
                f"systemd helper binding is missing {marker!r}"
            )
    for tasks in (guest_base, systemd):
        if "runpy.run_path" in tasks:
            raise AssertionError(
                "configure roles must route installed helper imports through "
                "the validated helper lifecycle"
            )

    py_compile.compile(
        str(DEPLOY_DIR / "files/strugglebus_inspector_contract.py"),
        doraise=True,
    )

    # Backup template receipt modification must have operation ID pattern.
    backup_template = (
        DEPLOY_DIR / "roles/systemd/templates/sqlite_backup.py.j2"
    ).read_text()
    if "OPERATION_ID_PATTERN" not in backup_template:
        raise AssertionError("backup template is missing operation ID pattern")
    if "_write_receipt" not in backup_template:
        raise AssertionError("backup template is missing receipt writer")
    if "--operation-id" not in backup_template:
        raise AssertionError("backup template is missing --operation-id arg")
    if "--receipt-dir" not in backup_template:
        raise AssertionError("backup template is missing --receipt-dir arg")
    # TOCTOU fix: receipt must use os.link, not os.rename after lexists.
    if "os.path.lexists(receipt_path)" in backup_template:
        raise AssertionError("backup template receipt uses TOCTOU-vulnerable lexists+rename")
    if "os.link(temporary, receipt_path)" not in backup_template:
        raise AssertionError("backup template receipt must use atomic os.link")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
