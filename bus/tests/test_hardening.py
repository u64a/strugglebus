"""Guards for someone else's network: full disks, restart loops, small mistakes."""

from __future__ import annotations

import io
from collections import namedtuple
from pathlib import Path

import pytest

from strugglebus import service
from strugglebus.config import AppConfig, ConfigurationError
from strugglebus.errors import MigrationError
from strugglebus.migrations import (
    PRE_MIGRATION_BACKUP_RETENTION, Migration, apply_migrations,
)
from test_migrations import connect
from test_rest_api import _agent_headers, _register, rest_client  # noqa: F401 - fixture

_Usage = namedtuple("_Usage", "total used free")
KIT = Path(__file__).resolve().parents[1] / "src" / "strugglebus" / "selfhost"


def test_interactive_api_pages_are_not_served(rest_client) -> None:  # noqa: F811
    # They load scripts from a public CDN; a LAN-only bus must not ask for that.
    for path in ("/docs", "/redoc", "/docs/oauth2-redirect"):
        response = rest_client.get(path, follow_redirects=False)
        assert response.status_code != 200, path
        assert "cdn.jsdelivr.net" not in response.text
    assert rest_client.get("/openapi.json").status_code == 200


def _token_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes) -> AppConfig:
    folder = tmp_path / "credentials"
    folder.mkdir(mode=0o700)
    path = folder / "admin-token"
    path.write_bytes(content)
    path.chmod(0o600)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(folder))
    return AppConfig(admin_credential_path=path)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_admin_token_file_may_end_with_one_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: bytes,
) -> None:
    token = b"a-long-random-admin-token-0123456789"
    config = _token_file(tmp_path, monkeypatch, token + ending)
    assert config.load_admin_secret() == token


def test_admin_token_keeps_other_whitespace_and_refuses_an_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Only the one line ending an editor adds is removed; anything else is the token.
    config = _token_file(tmp_path, monkeypatch, b"token with spaces \n\n")
    assert config.load_admin_secret() == b"token with spaces \n"
    (tmp_path / "credentials" / "admin-token").write_bytes(b"\n")
    with pytest.raises(ConfigurationError, match="holds no token"):
        config.load_admin_secret()


def test_serve_warns_about_a_short_admin_token_without_printing_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from strugglebus.cli import _serve_preflight

    config = _token_file(tmp_path, monkeypatch, b"hunter2\n")
    config = AppConfig(
        admin_credential_path=config.admin_credential_path, data_dir=tmp_path,
        database_path=tmp_path / "strugglebus.db", runtime_dir=tmp_path / "run",
        backup_dir=tmp_path / "backups", public_base_url="https://bus.lan",
    )
    output = io.StringIO()

    _serve_preflight(config, output)

    assert "only 7 characters long" in output.getvalue()
    assert "hunter2" not in output.getvalue()


def test_a_migration_that_keeps_failing_does_not_fill_the_backup_folder(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "upgrade.db"
    backup_dir = tmp_path / "backups"
    first = Migration(1, "0001_first.sql", "CREATE TABLE first (id INTEGER);")
    broken = Migration(2, "0002_broken.sql", "CREATE TABLE first (id INTEGER);")
    with connect(database_path) as database:
        assert apply_migrations(database, (first,)) == 1
        database.execute("INSERT INTO first (id) VALUES (?)", (7,))
        # What a restart loop does: the same failing upgrade, again and again.
        for _ in range(PRE_MIGRATION_BACKUP_RETENTION + 4):
            with pytest.raises(MigrationError):
                apply_migrations(
                    database, (first, broken),
                    database_path=database_path, backup_dir=backup_dir,
                )
        assert database.execute("PRAGMA user_version").fetchone()[0] == 1

    copies = sorted(backup_dir.glob("upgrade.db.v1.*.backup"))
    assert len(copies) == PRE_MIGRATION_BACKUP_RETENTION
    with connect(copies[-1]) as newest:
        assert newest.execute("SELECT id FROM first").fetchone()[0] == 7


def test_pruning_leaves_other_versions_and_scheduled_backups_alone(tmp_path: Path) -> None:
    database_path = tmp_path / "upgrade.db"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    kept = [
        backup_dir / "upgrade.db.v9.20260101T000000000000Z.backup",
        backup_dir / "strugglebus-20260101T000000000000Z.db",
        backup_dir / "other.db.v1.20260101T000000000000Z.backup",
    ]
    for path in kept:
        path.write_bytes(b"unrelated")
    first = Migration(1, "0001_first.sql", "CREATE TABLE first (id INTEGER);")
    broken = Migration(2, "0002_broken.sql", "CREATE TABLE first (id INTEGER);")
    with connect(database_path) as database:
        apply_migrations(database, (first,))
        for _ in range(PRE_MIGRATION_BACKUP_RETENTION + 2):
            with pytest.raises(MigrationError):
                apply_migrations(
                    database, (first, broken),
                    database_path=database_path, backup_dir=backup_dir,
                )
    assert all(path.read_bytes() == b"unrelated" for path in kept)


def test_posting_is_refused_when_the_disk_is_nearly_full_and_reading_still_works(
    rest_client, monkeypatch: pytest.MonkeyPatch,  # noqa: F811
) -> None:
    agent = _register(rest_client)
    headers = _agent_headers(agent)
    posted = rest_client.post(
        "/api/channels/status/messages", headers=headers, json={"body": "before"},
    )
    assert posted.status_code == 201, posted.text

    monkeypatch.setattr(
        service.shutil, "disk_usage",
        lambda path: _Usage(10**12, 10**12, service.MINIMUM_FREE_BYTES - 1),
    )
    refused = rest_client.post(
        "/api/channels/status/messages", headers=headers, json={"body": "after"},
    )
    assert refused.status_code == 507
    assert "out of disk space" in refused.json()["detail"]
    read = rest_client.get("/api/channels/status/messages", headers=headers)
    assert read.status_code == 200
    assert "after" not in read.text

    monkeypatch.setattr(
        service.shutil, "disk_usage",
        lambda path: _Usage(10**12, 0, service.MINIMUM_FREE_BYTES),
    )
    assert rest_client.post(
        "/api/channels/status/messages", headers=headers, json={"body": "room again"},
    ).status_code == 201


def test_self_host_health_checks_use_the_route_that_exists(rest_client) -> None:  # noqa: F811
    assert rest_client.get("/healthz").status_code == 200
    installer = (KIT / "debian" / "install.sh").read_text(encoding="utf-8")
    dockerfile = (KIT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    for text in (installer, dockerfile):
        assert "/healthz" in text and "/readyz" not in text


def test_gateways_refuse_visitors_from_outside_private_networks() -> None:
    for name, extra in (("debian", "__BUS_ALLOWED_CLIENTS__"), ("docker", "{$BUS_ALLOWED_CLIENTS}")):
        gateway = (KIT / name / "Caddyfile").read_text(encoding="utf-8")
        guard = (
            "@outside not remote_ip private_ranges 100.64.0.0/10 169.254.0.0/16 "
            f"fe80::/10 {extra}\n"
        )
        assert guard in gateway, name
        # The refusal comes before anything is passed to the application.
        assert gateway.index("respond @outside") < gateway.index("reverse_proxy 127.0.0.1:8080")
        assert " 403\n" in gateway.split("respond @outside", 1)[1].split("\n", 1)[0] + "\n"
    installer = (KIT / "debian" / "install.sh").read_text(encoding="utf-8")
    entrypoint = (KIT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    for script in (installer, entrypoint):
        # Neither install path can be talked into allowing the whole internet.
        assert "ipaddress.ip_network(text, strict=False).prefixlen == 0" in script
    assert "BUS_ALLOWED_CLIENTS: ${BUS_ALLOWED_CLIENTS:-}" in (
        KIT / "docker" / "compose.yaml"
    ).read_text(encoding="utf-8")
    guide = (KIT / "INSTALL.md").read_text(encoding="utf-8")
    assert "### Clients on other address ranges" in guide
