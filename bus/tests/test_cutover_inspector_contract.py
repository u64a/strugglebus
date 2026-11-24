"""Offline tests for the inspector contract verifier."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import patch

import pytest

from strugglebus.migrations import apply_migrations, load_packaged_migrations


REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = REPOSITORY / "deploy/files/strugglebus_inspector_contract.py"
INSPECTOR = (
    REPOSITORY / "deploy/roles/guest_base/files/strugglebus-inspect-access-freeze.py"
)
SPEC = importlib.util.spec_from_file_location("inspector_contract", HELPER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the inspector contract helper")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
InspectorContractError = MODULE.InspectorContractError
verify_inspector_contract = MODULE.verify_inspector_contract
_create_schema_database = MODULE._create_schema_database
SCHEMA_11_SQL = (
    REPOSITORY / "deploy/tests/inspector_schema_11.sql"
).read_text(encoding="utf-8")
DECISIONS = {
    *(f"schema_{version}_accepted" for version in range(6, 13)),
    "legacy_schema_unsupported",
    "schema_13_rejected",
    "future_schema_rejected",
    "malformed_schema_rejected",
}


class TestSchemaDatabase:
    @pytest.mark.parametrize("version", range(6, 14))
    @pytest.mark.parametrize("frozen", [False, True])
    def test_schema_and_freeze_fixture(
        self, tmp_path: Path, version: int, frozen: bool
    ) -> None:
        db = tmp_path / f"s{version}.db"
        _create_schema_database(db, version, frozen=frozen)
        with sqlite3.connect(db) as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == version
            assert conn.execute(
                "SELECT frozen FROM agent_access_state"
            ).fetchone()[0] == int(frozen)
            tables = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            assert {"agent_access_state", "agent_access_audit"} <= tables
            if version >= 10:
                assert {"agent_enrollments", "agent_enrollment_redemptions"} <= tables
            if version >= 12:
                assert {"agent_reconnect_grants", "agent_lifecycle_audit"} <= tables

    @pytest.mark.parametrize("version", [10, 11, 12])
    def test_offline_fixture_matches_real_packaged_layout(
        self, tmp_path: Path, version: int
    ) -> None:
        fixture = tmp_path / "fixture.db"
        _create_schema_database(fixture, version)
        with sqlite3.connect(":memory:") as real, sqlite3.connect(fixture) as offline:
            apply_migrations(real, load_packaged_migrations()[:version])
            query = """
                SELECT type, name, tbl_name, sql FROM sqlite_schema
                WHERE name NOT GLOB 'sqlite_*' ORDER BY type, name
            """
            real_layout = [
                (*row[:3], " ".join(row[3].split())) for row in real.execute(query)
            ]
            offline_layout = [
                (*row[:3], " ".join(row[3].split())) for row in offline.execute(query)
            ]
            assert offline_layout == real_layout


class TestContractVerification:
    def test_requires_absolute_paths(self) -> None:
        with pytest.raises(InspectorContractError, match="absolute"):
            verify_inspector_contract(Path("relative"), Path(sys.executable))

    def test_requires_absolute_python(self) -> None:
        with pytest.raises(InspectorContractError, match="absolute"):
            verify_inspector_contract(INSPECTOR, Path("python"))

    def test_real_inspector_and_exact_result(self) -> None:
        result = verify_inspector_contract(INSPECTOR, Path(sys.executable))
        assert result == {
            "contract_version": 3,
            **{key: True for key in DECISIONS},
            "passed": True,
        }
        assert len(json.dumps(result)) <= 1024

    @pytest.mark.parametrize("maximum", [9, 10, 11, 12, 2147483647])
    def test_version_only_inspector_never_passes(
        self, tmp_path: Path, maximum: int
    ) -> None:
        inspector = tmp_path / "version_only.py"
        inspector.write_text(
            "import json, sqlite3, sys\n"
            "db = sqlite3.connect(sys.argv[1])\n"
            "v = db.execute('PRAGMA user_version').fetchone()[0]\n"
            f"if v > {maximum}: sys.exit(1)\n"
            "frozen = bool(db.execute('SELECT frozen FROM agent_access_state')"
            ".fetchone()[0]) if v >= 6 else False\n"
            "print(json.dumps({'schema_supported': v >= 6, 'frozen': frozen}))\n",
            encoding="utf-8",
        )
        result = verify_inspector_contract(inspector, Path(sys.executable))
        assert result["schema_9_accepted"] is True
        assert result["schema_10_accepted"] is (maximum >= 10)
        assert result["schema_11_accepted"] is (maximum >= 11)
        assert result["schema_12_accepted"] is (maximum >= 12)
        assert result["schema_13_rejected"] is (maximum < 13)
        assert result["future_schema_rejected"] is (maximum < 2147483647)
        assert result["malformed_schema_rejected"] is (maximum < 10)
        assert result["passed"] is False

    def test_inspector_that_rejects_everything(self, tmp_path: Path) -> None:
        inspector = tmp_path / "reject_all.py"
        inspector.write_text("import sys; sys.exit(1)\n", encoding="utf-8")
        result = verify_inspector_contract(inspector, Path(sys.executable))
        for version in range(6, 13):
            assert result[f"schema_{version}_accepted"] is False
        assert result["legacy_schema_unsupported"] is False
        assert result["schema_13_rejected"] is True
        assert result["future_schema_rejected"] is True
        assert result["malformed_schema_rejected"] is True
        assert result["passed"] is False

    def test_exit_zero_without_decision_is_not_acceptance(self, tmp_path: Path) -> None:
        inspector = tmp_path / "accept_all.py"
        inspector.write_text("import sys; sys.exit(0)\n", encoding="utf-8")
        result = verify_inspector_contract(inspector, Path(sys.executable))
        assert result == {
            "contract_version": 3,
            **{key: False for key in DECISIONS},
            "passed": False,
        }

    def test_timeout_never_counts_as_future_rejection(self) -> None:
        with patch.object(
            MODULE.subprocess, "run",
            side_effect=subprocess.TimeoutExpired("inspector", 10),
        ):
            result = verify_inspector_contract(INSPECTOR, Path(sys.executable))
        assert result["schema_13_rejected"] is False
        assert result["future_schema_rejected"] is False
        assert result["passed"] is False

    def test_contract_closes_and_removes_fixture_databases(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with patch.object(
            MODULE.subprocess, "run",
            side_effect=subprocess.TimeoutExpired("inspector", 10),
        ):
            verify_inspector_contract(INSPECTOR, Path(sys.executable))
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.parametrize(
        ("returncode", "stdout", "stderr", "expected"),
        [
            (0, b'{"frozen":0,"schema_supported":1}', b"", {"frozen": False, "schema_supported": True}),
            (0, b'{"frozen":false,"schema_supported":true,"reason":"private"}', b"", {"frozen": False, "schema_supported": True}),
            (0, b'{"frozen":false,"schema_supported":true}', b"private", {"frozen": False, "schema_supported": True}),
            (0, b"{broken", b"", {"frozen": False, "schema_supported": True}),
            (0, b"\xff", b"", {"frozen": False, "schema_supported": True}),
            (0, b"x" * 1025, b"", {"frozen": False, "schema_supported": True}),
            (2, b"", b"", None),
            (1, b"private", b"", None),
        ],
    )
    def test_malformed_decisions_and_crashes_fail_closed(
        self, returncode: int, stdout: bytes, stderr: bytes,
        expected: dict[str, bool] | None,
    ) -> None:
        result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with patch.object(MODULE.subprocess, "run", return_value=result):
            assert MODULE._check_inspector(
                INSPECTOR, Path(sys.executable), REPOSITORY / "not-opened.db", expected
            ) is False

    def test_missing_python_is_a_contract_error(self) -> None:
        with patch.object(MODULE.subprocess, "run", side_effect=FileNotFoundError):
            with pytest.raises(InspectorContractError, match="could not be executed"):
                verify_inspector_contract(INSPECTOR, Path(sys.executable))

    def test_cli_exact_result(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", str(HELPER), str(INSPECTOR), sys.executable],
            capture_output=True, timeout=180, check=False,
        )
        assert result.returncode == 0
        assert result.stderr == b""
        payload = json.loads(result.stdout)
        assert set(payload) == DECISIONS | {"contract_version", "passed"}
        assert payload["contract_version"] == 3
        assert payload["passed"] is True
