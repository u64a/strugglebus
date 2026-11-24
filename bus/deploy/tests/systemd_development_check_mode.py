"""Validate the development-only backup timer check-mode exception."""

from __future__ import annotations

from pathlib import Path


DEPLOY_DIR = Path(__file__).resolve().parents[1]
TASKS_PATH = DEPLOY_DIR / "roles/systemd/tasks/backup_timer.yml"


def require(marker: str, body: str) -> None:
    if marker not in body:
        raise AssertionError(f"backup timer contract is missing {marker!r}")


def main() -> int:
    body = TASKS_PATH.read_text(encoding="utf-8")
    enable_name = "- name: Enable the daily backup timer"
    prediction_name = (
        "- name: Report backup timer enablement predicted by development check mode"
    )
    require(enable_name, body)
    require(prediction_name, body)

    enable_start = body.index(enable_name)
    prediction_start = body.index(prediction_name)
    if prediction_start <= enable_start:
        raise AssertionError("backup timer prediction must follow real enablement")
    enable = body[enable_start:prediction_start]
    prediction = body[prediction_start:]

    for marker in (
        "ansible.builtin.systemd_service:",
        "name: strugglebus-backup.timer",
        "enabled: true",
        "not (",
        "ansible_check_mode",
        'strugglebus_deployment_profile | default("production")',
        ') == "development"',
    ):
        require(marker, enable)
    for marker in (
        "ansible.builtin.debug:",
        "changed_when: true",
        "- ansible_check_mode",
        'strugglebus_deployment_profile | default("production")',
        '== "development"',
    ):
        require(marker, prediction)
    if enable.count(
        'strugglebus_deployment_profile | default("production")'
    ) != 1:
        raise AssertionError("real timer enablement must have one development guard")
    if prediction.count(
        'strugglebus_deployment_profile | default("production")'
    ) != 1:
        raise AssertionError("timer prediction must have one development guard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
