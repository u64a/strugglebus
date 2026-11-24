from __future__ import annotations

import builtins
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from release_fixtures import load_script


state = load_script("promotion_state")
PromotionError = state.PromotionError
LINUX = sys.platform == "linux" and os.name == "posix"


def test_native_windows_refused_before_filesystem_access(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(state.sys, "platform", "win32")
    with pytest.raises(PromotionError, match="native Windows is not supported"):
        state.ReceiptStore(tmp_path / "receipt.json")
    assert list(tmp_path.iterdir()) == []


def test_canonical_encoding_has_sorted_ascii_keys_and_newline() -> None:
    document = {"z": ["caf\u00e9", True, None], "a": {"z": 2, "a": 1}}
    payload = b'{"a":{"a":1,"z":2},"z":["caf\\u00e9",true,null]}\n'
    assert state._canonical(document) == payload
    assert state._decode(payload) == document


@pytest.mark.parametrize(
    "payload",
    [
        b"", b"{", b"{}\n\n", b"{}", b" {}\n", b'{"z":0,"a":0}\n',
        b'{"x":1,"x":2}\n', b'{"x":{"a":0,"a":1}}\n',
        b'{"x":NaN}\n', b'{"x":Infinity}\n', b'{"x":-Infinity}\n',
        b'{"x":1e400}\n', b'{"x":1e0}\n', b'{"x":01}\n',
        b'{"x": "\\u0061"}\n', b"\xef\xbb\xbf{}\n",
        '{"x":"caf\u00e9"}\n'.encode(), b"[]\n", b"null\n", b"true\n",
    ],
)
def test_noncanonical_or_invalid_json_is_refused(payload: bytes) -> None:
    with pytest.raises(PromotionError):
        state._decode(payload)


@pytest.mark.parametrize(
    "document",
    [
        [], None, {"x": {1: "one"}}, {True: "true"}, {"x": b"bytes"},
        {"x": (1, 2)}, {"x": float("nan")}, {"x": float("inf")},
        {"x": object()},
    ],
)
def test_only_strict_json_objects_can_be_encoded(document) -> None:
    with pytest.raises(PromotionError):
        state._canonical(document)


def test_encoding_and_decoding_enforce_exact_64kib_boundary() -> None:
    overhead = len(b'{"x":""}\n')
    document = {"x": "a" * (state.MAX_RECEIPT_BYTES - overhead)}
    payload = state._canonical(document)
    assert len(payload) == 64 * 1024
    assert state._decode(payload) == document
    with pytest.raises(PromotionError, match="64 KiB"):
        state._canonical({"x": document["x"] + "a"})
    with pytest.raises(PromotionError, match="64 KiB"):
        state._decode(payload + b"\n")


def test_deep_or_cyclic_json_fails_with_safe_error() -> None:
    document: dict = {}
    document["cycle"] = document
    with pytest.raises(PromotionError):
        state._canonical(document)
    with pytest.raises(PromotionError):
        state._decode(b'{"x":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}\n")


def write_raw(path: Path, payload: bytes = b'{"phase":"old"}\n') -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


@pytest.mark.skipif(not LINUX, reason="actual Linux openat, mount identity, modes, and flock")
class TestLinuxReceiptStore:
    @pytest.fixture
    def store(self, tmp_path: Path):
        tmp_path.chmod(0o700)
        return state.ReceiptStore(tmp_path / "receipt.json")

    def test_missing_read_and_unlocked_write_do_not_create_anything(self, store) -> None:
        assert store.path.is_absolute()
        before = store.path.parent.stat().st_mtime_ns
        with pytest.raises(PromotionError, match="does not exist"):
            store.read()
        with pytest.raises(PromotionError, match="active exclusive lock"):
            store.write({"phase": "new"}, create=True)
        assert list(store.path.parent.iterdir()) == []
        assert store.path.parent.stat().st_mtime_ns == before

    def test_existing_read_does_not_create_or_acquire_lock(self, store) -> None:
        write_raw(store.path)
        before = store.path.stat()
        assert store.read() == {"phase": "old"}
        assert [entry.name for entry in store.path.parent.iterdir()] == ["receipt.json"]
        assert store.path.stat().st_mtime_ns == before.st_mtime_ns
        with store.locked():
            assert state.ReceiptStore(store.path).read() == {"phase": "old"}

    def test_create_replace_and_stable_lock(self, store) -> None:
        lock = store.path.with_name("receipt.json.lock")
        with store.locked() as held:
            assert held is store
            lock_inode = lock.stat().st_ino
            assert not store.path.exists()
            store.write({"phase": "initial"}, create=True)
            first_inode = store.path.stat().st_ino
            store.write({"phase": "next"})
            assert store.path.stat().st_ino != first_inode
            assert lock.stat().st_ino == lock_inode
            with pytest.raises(PromotionError, match="locked"):
                with state.ReceiptStore(store.path).locked():
                    pytest.fail("second writer acquired the lock")
        assert store.read() == {"phase": "next"}
        assert store.path.read_bytes() == b'{"phase":"next"}\n'
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
        assert store.path.stat().st_nlink == 1
        assert lock.exists() and lock.stat().st_ino == lock_inode
        with store.locked():
            assert lock.stat().st_ino == lock_inode

    @pytest.mark.parametrize("payload", [b'{"phase":"old"}\n', b"{", b'{"x":0,"x":1}\n'])
    def test_create_never_clobbers_existing_state(self, store, payload: bytes) -> None:
        write_raw(store.path, payload)
        with store.locked():
            with pytest.raises(PromotionError, match="already exists"):
                store.write({"phase": "new"}, create=True)
        assert store.path.read_bytes() == payload

    @pytest.mark.parametrize("payload", [b"{", b'{"x":0,"x":1}\n', b"{}", b'{"z":0,"a":0}\n'])
    def test_update_never_resets_malformed_state(self, store, payload: bytes) -> None:
        write_raw(store.path, payload)
        with store.locked():
            with pytest.raises(PromotionError):
                store.read()
            with pytest.raises(PromotionError):
                store.write({"phase": "new"})
        assert store.path.read_bytes() == payload

    def test_update_requires_existing_receipt(self, store) -> None:
        with store.locked():
            with pytest.raises(PromotionError, match="does not exist"):
                store.write({"phase": "new"})
        assert not store.path.exists()
        assert sorted(p.name for p in store.path.parent.iterdir()) == ["receipt.json.lock"]

    def test_receipt_size_bound_on_disk_and_during_save(self, store) -> None:
        document = {"x": "a" * (state.MAX_RECEIPT_BYTES - len(b'{"x":""}\n'))}
        with store.locked():
            store.write(document, create=True)
            assert store.read() == document
            with pytest.raises(PromotionError, match="64 KiB"):
                store.write({"x": document["x"] + "a"})
        with store.path.open("ab") as stream:
            stream.write(b"\n")
        with pytest.raises(PromotionError, match="64 KiB"):
            store.read()

    @pytest.mark.parametrize("mode", [0o400, 0o644, 0o660, 0o700, 0o1600])
    @pytest.mark.parametrize("name", ["receipt.json", "receipt.json.lock"])
    def test_unsafe_file_modes_are_never_repaired(self, store, mode: int, name: str) -> None:
        target = store.path.parent / name
        write_raw(target)
        target.chmod(mode)
        if name == "receipt.json":
            with pytest.raises(PromotionError, match="0600"):
                store.read()
        else:
            with pytest.raises(PromotionError, match="0600"):
                with store.locked():
                    pytest.fail("unsafe lock accepted")
        assert stat.S_IMODE(target.stat().st_mode) == mode

    @pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "fifo"])
    @pytest.mark.parametrize("name", ["receipt.json", "receipt.json.lock"])
    def test_special_files_and_links_are_refused(self, store, kind: str, name: str) -> None:
        target = store.path.parent / name
        source = store.path.parent / "original"
        write_raw(source)
        if kind == "symlink":
            target.symlink_to(source)
        elif kind == "hardlink":
            os.link(source, target)
        elif kind == "directory":
            target.mkdir(mode=0o700)
        else:
            os.mkfifo(target, mode=0o600)
        if name == "receipt.json":
            with pytest.raises(PromotionError, match="regular file"):
                store.read()
        else:
            with pytest.raises(PromotionError, match="regular file"):
                with store.locked():
                    pytest.fail("unsafe lock accepted")
        assert source.read_bytes() == b'{"phase":"old"}\n'

    @pytest.mark.parametrize("mode", [0o755, 0o770, 0o1700, 0o1777])
    def test_parent_must_be_exactly_0700(self, store, mode: int) -> None:
        store.path.parent.chmod(mode)
        with pytest.raises(PromotionError, match="0700"):
            store.read()
        assert list(store.path.parent.iterdir()) == []

    def test_missing_parent_is_not_created(self, store) -> None:
        missing = state.ReceiptStore(store.path.parent / "missing" / "receipt.json")
        with pytest.raises(PromotionError, match="preexisting"):
            missing.read()
        with pytest.raises(PromotionError, match="preexisting"):
            with missing.locked():
                pytest.fail("missing directory accepted")
        assert list(store.path.parent.iterdir()) == []

    @pytest.mark.parametrize("kind", ["relative", "parent-traversal", "root"])
    def test_invalid_paths_are_refused(self, store, kind: str) -> None:
        path = {
            "relative": Path("receipt.json"),
            "parent-traversal": store.path.parent / ".." / "receipt.json",
            "root": Path("/"),
        }[kind]
        with pytest.raises(PromotionError, match="absolute"):
            state.ReceiptStore(path)

    def test_symlink_ancestors_are_refused(self, store) -> None:
        actual = store.path.parent / "actual"
        actual.mkdir(mode=0o700)
        alias = store.path.parent / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with pytest.raises(PromotionError, match="symlink"):
            state.ReceiptStore(alias / "receipt.json").read()
        assert list(actual.iterdir()) == []

    def test_unsafe_ancestor_is_refused_even_with_private_parent(self, store) -> None:
        parent = store.path.parent / "private"
        parent.mkdir(mode=0o700)
        store.path.parent.chmod(0o777)
        with pytest.raises(PromotionError, match="ancestors"):
            state.ReceiptStore(parent / "receipt.json").read()
        assert list(parent.iterdir()) == []

    @pytest.mark.parametrize("path", ["/tmp", "/var/tmp"])
    def test_only_os_sticky_temp_ancestor_exception(self, path: str) -> None:
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
        state._directory(info, Path(path), parent=False)
        with pytest.raises(PromotionError, match="0700"):
            state._directory(info, Path(path), parent=True)
        with pytest.raises(PromotionError, match="ancestors"):
            state._directory(info, Path("/unsafe-sticky"), parent=False)

    def test_foreign_file_and_directory_owners_are_refused(self, store) -> None:
        foreign = os.geteuid() + 1000
        with pytest.raises(PromotionError, match="current-owner"):
            state._regular(
                SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=foreign, st_nlink=1),
                "receipt",
            )
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=foreign)
        with pytest.raises(PromotionError, match="current-owner"):
            state._directory(info, store.path.parent, parent=True)
        with pytest.raises(PromotionError, match="ancestors"):
            state._directory(info, store.path.parent, parent=False)

    @pytest.mark.parametrize("filesystem", ["9p", "drvfs", "nfs", "nfs4", "cifs", "fuse", "overlay"])
    def test_non_native_or_network_mounts_are_refused(self, monkeypatch, filesystem: str) -> None:
        def fake_open(path, mode):
            if path == "/proc/self/fdinfo/42":
                return io.BytesIO(b"pos:\t0\nmnt_id:\t19\n")
            assert path == "/proc/self/mountinfo"
            return io.BytesIO(f"19 1 0:1 / / rw - {filesystem} source rw\n".encode())

        monkeypatch.setattr(builtins, "open", fake_open)
        with pytest.raises(PromotionError, match="native local Linux"):
            state._local_storage(42)

    def test_mountinfo_is_bounded_and_mount_must_be_identifiable(self, monkeypatch) -> None:
        for fdinfo, mounts in [
            (b"missing identity\n", b""),
            (b"mnt_id:\t19\n", b""),
            (b"mnt_id:\t19\n", b"x" * (state._PROC_LIMIT + 1)),
        ]:
            def fake_open(path, mode):
                return io.BytesIO(fdinfo if "/fdinfo/" in path else mounts)

            monkeypatch.setattr(builtins, "open", fake_open)
            with pytest.raises(PromotionError):
                state._local_storage(42)

    def test_receipt_replacement_between_stat_and_open_is_refused(self, store, monkeypatch) -> None:
        write_raw(store.path)
        real_open = state.os.open

        def race_open(path, flags, *args, **kwargs):
            if path == store.path.name:
                replacement = store.path.parent / "replacement"
                write_raw(replacement, b'{"phase":"other"}\n')
                os.replace(replacement, store.path)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(state.os, "open", race_open)
        with pytest.raises(PromotionError, match="changed while opening"):
            store.read()

    def test_receipt_modified_during_read_is_refused(self, store, monkeypatch) -> None:
        write_raw(store.path)
        real_read = state.os.read
        modified = False

        def race_read(fd, count):
            nonlocal modified
            chunk = real_read(fd, count)
            if not modified:
                modified = True
                write_raw(store.path, b'{"phase":"changed"}\n')
            return chunk

        monkeypatch.setattr(state.os, "read", race_read)
        with pytest.raises(PromotionError, match="changed during reading"):
            store.read()

    def test_changed_previously_read_state_is_not_overwritten(self, store) -> None:
        write_raw(store.path)
        with store.locked():
            store.read()
            write_raw(store.path, b'{"phase":"external-edit"}\n')
            with pytest.raises(PromotionError, match="changed since"):
                store.write({"phase": "new"})
        assert store.read() == {"phase": "external-edit"}

    def test_parent_replacement_is_detected(self, store) -> None:
        original = store.path.parent
        moved = original.with_name(original.name + "-moved")
        with store.locked():
            original.rename(moved)
            original.mkdir(mode=0o700)
            with pytest.raises(PromotionError, match="directory identity changed"):
                store.write({"phase": "new"}, create=True)
        assert list(original.iterdir()) == []
        assert [p.name for p in moved.iterdir()] == ["receipt.json.lock"]

    def test_replaced_lock_cannot_split_exclusion(self, store) -> None:
        lock = store.path.with_name("receipt.json.lock")
        with store.locked():
            store.write({"phase": "initial"}, create=True)
            replacement = store.path.parent / "new-lock"
            write_raw(replacement, b"")
            os.replace(replacement, lock)
            with pytest.raises(PromotionError, match="locked"):
                with state.ReceiptStore(store.path).locked():
                    pytest.fail("replacement lock split mutual exclusion")
            with pytest.raises(PromotionError, match="stable receipt lock was replaced"):
                store.write({"phase": "new"})
        assert store.read() == {"phase": "initial"}

    def test_lock_cannot_be_reentered_and_exception_releases_it(self, store) -> None:
        with pytest.raises(RuntimeError, match="injected"):
            with store.locked():
                with pytest.raises(PromotionError, match="already active"):
                    with store.locked():
                        pytest.fail("reentrant lock accepted")
                raise RuntimeError("injected")
        with store.locked():
            store.write({}, create=True)

    def test_sibling_inode_itself_is_exclusively_locked(self, store) -> None:
        import fcntl

        lock = store.path.with_name("receipt.json.lock")
        with store.locked():
            with lock.open("rb") as contender:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with lock.open("rb") as independent:
            fcntl.flock(independent.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(PromotionError, match="locked"):
                with store.locked():
                    pytest.fail("a held sibling lock was ignored")
        with store.locked():
            store.write({}, create=True)

    def test_removed_lock_is_explicitly_refused(self, store) -> None:
        with store.locked():
            store.path.with_name("receipt.json.lock").unlink()
            with pytest.raises(PromotionError, match="stable receipt lock was removed"):
                store.write({}, create=True)
        assert not store.path.exists()

    def test_cross_process_exclusion_survives_atomic_receipt_replacement(self, store) -> None:
        code = (
            "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "from promotion_state import ReceiptStore, PromotionError\n"
            "try:\n"
            " with ReceiptStore(Path(sys.argv[2])).locked() as store:\n"
            "  store.write({'phase': 'child'})\n"
            "except PromotionError as error:\n"
            " print(str(error)); raise SystemExit(error.code)\n"
        )
        command = [sys.executable, "-c", code, str(Path(state.__file__).parent), str(store.path)]
        with store.locked():
            store.write({"phase": "initial"}, create=True)
            store.write({"phase": "replaced"})
            blocked = subprocess.run(command, capture_output=True, text=True, timeout=10)
            assert blocked.returncode == 6
            assert "locked" in blocked.stdout
            assert not blocked.stderr
        accepted = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert accepted.returncode == 0, accepted.stderr
        assert store.read() == {"phase": "child"}

    def test_create_race_does_not_overwrite_newly_existing_file(self, store, monkeypatch) -> None:
        real_rename = state._rename_create

        def competing_create(source, target, parent_fd):
            write_raw(store.path, b'{"phase":"other"}\n')
            real_rename(source, target, parent_fd)

        monkeypatch.setattr(state, "_rename_create", competing_create)
        with store.locked():
            with pytest.raises(PromotionError, match="already exists"):
                store.write({"phase": "new"}, create=True)
        assert store.read() == {"phase": "other"}
        assert sorted(p.name for p in store.path.parent.iterdir()) == [
            "receipt.json", "receipt.json.lock"
        ]

    def test_fsync_and_replace_order(self, store, monkeypatch) -> None:
        with store.locked():
            store.write({"phase": "old"}, create=True)
            events: list[str] = []
            real_fsync, real_replace = state.os.fsync, state.os.replace

            def sync(fd):
                events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
                real_fsync(fd)

            def replace(*args, **kwargs):
                events.append("replace")
                real_replace(*args, **kwargs)

            monkeypatch.setattr(state.os, "fsync", sync)
            monkeypatch.setattr(state.os, "replace", replace)
            store.write({"phase": "new"})
            assert events == ["file", "replace", "directory"]

    @pytest.mark.parametrize("stage", ["file", "replace", "directory"])
    def test_faults_leave_old_or_new_state_and_only_clean_own_temporary(
        self, store, monkeypatch, stage: str
    ) -> None:
        unrelated = store.path.parent / ".promotion-unrelated.tmp"
        write_raw(unrelated, b"unrelated data")
        with store.locked():
            store.write({"phase": "old"}, create=True)
            real_fsync = state.os.fsync

            def sync(fd):
                kind = "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
                if stage == kind:
                    raise OSError("injected private error")
                real_fsync(fd)

            def replace(*args, **kwargs):
                raise OSError("injected private error")

            monkeypatch.setattr(state.os, "fsync", sync)
            if stage == "replace":
                monkeypatch.setattr(state.os, "replace", replace)
            with pytest.raises(PromotionError, match="durability") as caught:
                store.write({"phase": "new"})
            assert "injected" not in str(caught.value)
        assert store.read() == {"phase": "new" if stage == "directory" else "old"}
        assert unrelated.read_bytes() == b"unrelated data"
        assert sorted(p.name for p in store.path.parent.iterdir()) == [
            ".promotion-unrelated.tmp", "receipt.json", "receipt.json.lock"
        ]

    def test_exclusive_temporary_collision_is_not_removed(self, store, monkeypatch) -> None:
        monkeypatch.setattr(state.secrets, "token_hex", lambda count: "a" * 32)
        collision = store.path.parent / (".promotion-" + "a" * 32 + ".tmp")
        write_raw(collision, b"not our temporary")
        with store.locked():
            with pytest.raises(PromotionError):
                store.write({}, create=True)
        assert collision.read_bytes() == b"not our temporary"
        assert not store.path.exists()

    def test_partial_system_writes_are_completed(self, store, monkeypatch) -> None:
        real_write = state.os.write
        calls = 0

        def partial_write(fd, payload):
            nonlocal calls
            calls += 1
            return real_write(fd, payload[:2])

        with store.locked():
            monkeypatch.setattr(state.os, "write", partial_write)
            store.write({"phase": "new"}, create=True)
        assert calls > 1
        assert store.read() == {"phase": "new"}

    def test_replaced_temporary_is_not_promoted_or_removed(self, store, monkeypatch) -> None:
        name = ".promotion-" + "b" * 32 + ".tmp"
        monkeypatch.setattr(state.secrets, "token_hex", lambda count: "b" * 32)
        temporary = store.path.parent / name
        real_fsync = state.os.fsync

        def sync_and_replace(fd):
            real_fsync(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode):
                replacement = store.path.parent / "other-file"
                write_raw(replacement, b"not our temporary")
                os.replace(replacement, temporary)

        with store.locked():
            monkeypatch.setattr(state.os, "fsync", sync_and_replace)
            with pytest.raises(PromotionError):
                store.write({}, create=True)
        assert not store.path.exists()
        assert temporary.read_bytes() == b"not our temporary"
