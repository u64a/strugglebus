"""Issue #16: errors are never silent, logging never crashes the host, and the 3.11 rmtree TypeError."""
from __future__ import annotations

import argparse
import json
import os
import types

import pytest

from workerhost import cli, state, vault
from workerhost.config import Config
from workerhost.logs import HostLog


def raise_and_catch(exc):
    try:
        raise exc
    except BaseException as e:  # noqa: BLE001
        return e


def test_error_writes_a_line_and_one_timestamped_block_per_error(tmp_path):
    log = HostLog(tmp_path)
    log.error("loop-error", raise_and_catch(TypeError("first")))
    log.error("loop-error", raise_and_catch(KeyError("second")), task_id="t1")
    lines = next(tmp_path.glob("host-*[0-9].log")).read_text(encoding="utf-8").splitlines()
    assert lines[0].endswith("loop-error error=TypeError message=first")
    assert "error=KeyError message='second' task_id=t1".replace("'", "_") in lines[1]
    blocks = next(tmp_path.glob("host-*.errors.log")).read_text(encoding="utf-8").split("\n\n")
    blocks = [b for b in blocks if b.strip()]
    assert len(blocks) == 2
    assert blocks[0].startswith("===== 20") and "loop-error TypeError =====" in blocks[0]
    assert "Traceback (most recent call last)" in blocks[0] and "TypeError: first" in blocks[0]
    assert "KeyError" in blocks[1]


def test_logging_never_raises(tmp_path):
    blocker = tmp_path / "logs"
    blocker.write_text("a file where the folder should be", encoding="utf-8")
    log = HostLog(blocker)
    log("event", a=1)
    log.error("loop-error", raise_and_catch(OSError("disk")))


def test_cmd_run_logs_a_fatal_error_in_host_construction(tmp_path, monkeypatch):
    def broken(cfg, echo=False):
        raise ValueError("bad config")

    monkeypatch.setattr(cli, "Host", broken)
    cfg = Config(host_name="alpha", home=tmp_path / "home")
    with pytest.raises(ValueError):
        cli.cmd_run(cfg, argparse.Namespace(echo=False, max_seconds=None))
    assert "fatal error=ValueError message=bad_config" in "".join(
        p.read_text(encoding="utf-8") for p in cfg.logs_dir.glob("host-*[0-9].log"))
    assert "ValueError: bad config" in next(cfg.logs_dir.glob("host-*.errors.log")).read_text(encoding="utf-8")


def test_remove_tree_uses_onerror_on_python_311(tmp_path, monkeypatch):
    """`shutil.rmtree(onexc=)` is 3.12+; install.ps1 accepts 3.11, where it raised TypeError after every
    finished worker (Host.end -> remove_tree)."""
    calls = []

    def rmtree_311(path, ignore_errors=False, onerror=None):
        calls.append(onerror)

    monkeypatch.setattr(vault, "sys", types.SimpleNamespace(version_info=(3, 11, 9)))
    monkeypatch.setattr(vault.shutil, "rmtree", rmtree_311)
    vault.remove_tree(tmp_path / "x")
    assert len(calls) == 1 and callable(calls[0])


def test_remove_tree_removes_a_read_only_tree(tmp_path):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    f = root / "sub" / "ro.txt"
    f.write_text("x", encoding="utf-8")
    f.chmod(0o444)
    vault.remove_tree(root)
    assert not root.exists()


@pytest.mark.skipif(os.name != "nt", reason="the replace-over-an-open-file failure is Windows behaviour")
def test_atomic_write_retries_while_a_reader_holds_the_file(tmp_path, monkeypatch):
    target = tmp_path / "status.json"
    target.write_text("{}", encoding="utf-8")
    reader = open(target, "rb")  # noqa: SIM115
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 3:
            reader.close()

    monkeypatch.setattr(state.time, "sleep", sleep)
    try:
        state.atomic_write_json(target, {"ok": 1})
    finally:
        reader.close()
    assert len(waits) == 3 and json.loads(target.read_text(encoding="utf-8")) == {"ok": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["status.json"]


def test_a_surrogate_in_an_error_message_does_not_break_logging(tmp_path):
    log = HostLog(tmp_path)
    log.error("loop-error", raise_and_catch(ValueError("bad \udcff byte")))
    assert "ValueError" in next(tmp_path.glob("host-*.errors.log")).read_text(encoding="utf-8")
