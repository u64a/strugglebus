"""Offline destination-confinement tests for the public CA exporter."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile


DEPLOY_DIR = Path(__file__).resolve().parents[1]
HELPER_PATH = DEPLOY_DIR / "files/export_caddy_ca.py"
PLAYBOOK_PATH = DEPLOY_DIR / "playbooks/export_ca.yml"
SPEC = importlib.util.spec_from_file_location("export_caddy_ca", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("CA export helper could not be loaded")
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)

CERTIFICATE = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"YWJj\n"
    b"-----END CERTIFICATE-----\n"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_refused(function) -> None:
    try:
        function()
    except exporter.ExportError:
        return
    raise AssertionError("unsafe export destination was accepted")


def secure_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = secure_directory(root / "repo")
        outside = secure_directory(root / "repo-boundary")

        expect_refused(
            lambda: exporter.resolve_destination(
                "relative", repository_root=repository
            )
        )
        descendant = secure_directory(repository / "artifact")
        expect_refused(
            lambda: exporter.resolve_destination(
                str(descendant), repository_root=repository
            )
        )
        regular_file = root / "file"
        regular_file.write_text("not a directory", encoding="ascii")
        expect_refused(
            lambda: exporter.resolve_destination(
                str(regular_file), repository_root=repository
            )
        )
        unsafe = secure_directory(root / "unsafe")
        if os.name != "nt":
            unsafe.chmod(0o755)
            expect_refused(
                lambda: exporter.resolve_destination(
                    str(unsafe), repository_root=repository
                )
            )
        symlink = root / "linked"
        try:
            symlink.symlink_to(outside, target_is_directory=True)
        except OSError:
            # Unprivileged native Windows lacks symbolic-link creation capability.
            pass
        else:
            expect_refused(
                lambda: exporter.resolve_destination(
                    str(symlink), repository_root=repository
                )
            )

        resolved, windows_path = exporter.resolve_destination(
            str(outside), repository_root=repository
        )
        require(resolved == outside.resolve(), "outside path was not canonicalized")
        require(
            (windows_path is not None) is (os.name == "nt"),
            "native Windows path classification is incorrect",
        )

        wsl_checks: list[tuple[str, bool]] = []

        def windows_security(path: str, *, expect_directory: bool) -> bool:
            wsl_checks.append((path, expect_directory))
            return True

        resolved, windows_path = exporter.resolve_destination(
            r"C:\Users\owner\artifacts",
            repository_root=repository,
            windows_security=windows_security,
            wsl_resolver=lambda _: (outside, r"C:\Users\owner\artifacts"),
        )
        require(resolved == outside.resolve(), "WSL path was not canonicalized")
        require(
            windows_path == r"C:\Users\owner\artifacts",
            "Windows artifact path was changed",
        )
        require(
            wsl_checks == [(windows_path, True)],
            "WSL destination did not receive authoritative ACL validation",
        )
        expect_refused(
            lambda: exporter.resolve_destination(
                r"C:\Users\owner\artifacts",
                repository_root=repository,
                windows_security=lambda *_args, **_kwargs: False,
                wsl_resolver=lambda _: (outside, r"C:\Users\owner\artifacts"),
            )
        )

        wsl_export = secure_directory(root / "wsl-export")
        moves: list[tuple[str, str]] = []

        def windows_move(source: str, destination: str) -> None:
            moves.append((source, destination))
            os.replace(
                wsl_export / Path(source.replace("\\", "/")).name,
                wsl_export / Path(destination.replace("\\", "/")).name,
            )

        exporter.export_certificate(
            r"C:\Users\owner\artifacts",
            CERTIFICATE,
            repository_root=repository,
            windows_security=lambda *_args, **_kwargs: True,
            windows_move=windows_move,
            wsl_resolver=lambda _: (
                wsl_export,
                r"C:\Users\owner\artifacts",
            ),
        )
        require(len(moves) == 2, "WSL export did not use Windows atomic moves")
        require(
            (wsl_export / exporter.CERTIFICATE_NAME).read_bytes() == CERTIFICATE,
            "WSL public certificate export failed",
        )

        stale_dir = secure_directory(root / "stale")
        (stale_dir / f"{exporter.TEMPORARY_PREFIX}old.tmp").write_bytes(b"")
        expect_refused(
            lambda: exporter.export_certificate(
                str(stale_dir),
                CERTIFICATE,
                repository_root=repository,
            )
        )

        target_dir = secure_directory(root / "target")
        (target_dir / exporter.CERTIFICATE_NAME).write_bytes(b"unexpected")
        expect_refused(
            lambda: exporter.export_certificate(
                str(target_dir),
                CERTIFICATE,
                repository_root=repository,
            )
        )

        rollback_dir = secure_directory(root / "rollback")
        publish_calls = 0

        def fail_second(source: Path, target: Path) -> None:
            nonlocal publish_calls
            publish_calls += 1
            if publish_calls == 2:
                raise OSError("injected write failure")
            os.link(source, target)

        try:
            exporter.export_certificate(
                str(rollback_dir),
                CERTIFICATE,
                repository_root=repository,
                publish=fail_second,
            )
        except OSError:
            pass
        else:
            raise AssertionError("injected publish failure unexpectedly succeeded")
        require(
            list(rollback_dir.iterdir()) == [],
            "failed publication was not rolled back",
        )

        success_dir = secure_directory(root / "success")
        exporter.export_certificate(
            str(success_dir),
            CERTIFICATE,
            repository_root=repository,
        )
        certificate = success_dir / exporter.CERTIFICATE_NAME
        instructions = success_dir / exporter.INSTRUCTIONS_NAME
        require(
            certificate.read_bytes() == CERTIFICATE,
            "exported public certificate changed",
        )
        if os.name == "nt":
            require(
                exporter._windows_security(
                    str(certificate), expect_directory=False
                ),
                "certificate ACL is unsafe",
            )
            require(
                exporter._windows_security(
                    str(instructions), expect_directory=False
                ),
                "instructions ACL is unsafe",
            )
        else:
            require(
                certificate.stat().st_mode & 0o777 == 0o644,
                "certificate mode is unsafe",
            )
            require(
                instructions.stat().st_mode & 0o777 == 0o644,
                "instructions mode is unsafe",
            )
        expected = ":".join(
            hashlib.sha256(b"abc").hexdigest().upper()[index : index + 2]
            for index in range(0, 64, 2)
        )
        require(
            f"SHA-256 fingerprint: {expected}"
            in instructions.read_text(encoding="ascii"),
            "certificate fingerprint is incorrect",
        )
        exporter.export_certificate(
            str(success_dir),
            CERTIFICATE,
            repository_root=repository,
        )
        require(
            len(list(success_dir.iterdir())) == 2,
            "idempotent export created extra files",
        )

    helper = HELPER_PATH.read_text(encoding="utf-8").lower()
    playbook = PLAYBOOK_PATH.read_text(encoding="utf-8").lower()
    require(".key" not in helper, "export helper references signing material")
    require(".key" not in playbook, "export playbook references signing material")
    require(
        "certificate_base64" in playbook,
        "export playbook does not pass only certificate material",
    )
    require(
        "ansible.builtin.command" in playbook,
        "export helper command boundary is missing",
    )
    require(
        "no_log: true" in playbook,
        "certificate-bearing export task is not hidden",
    )
    require(
        "report only the sanitized ca export result" in playbook,
        "sanitized CA export refusal is not observable",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
