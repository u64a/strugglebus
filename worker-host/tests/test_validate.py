"""The validator (design section 3): every rule, in order. A message is data, never a command."""
from __future__ import annotations

import json
import os
import subprocess
from datetime import timedelta

import pytest

from conftest import BRIEF, COMMIT, COORD, NOW, STRANGER, FakeVault, message, task_body
from workerhost.validate import MAX_BODY_BYTES, Pin, classify, digest_of, validate_task


def test_valid_task_is_accepted(ctx):
    d = validate_task(message(task_body()), ctx)
    assert d.action == "accept", d
    assert d.brief.text.startswith("Build")
    assert d.digest == digest_of(task_body())


# --- step 1: sender -----------------------------------------------------------------------------

@pytest.mark.parametrize("sender", [
    Pin("22222222-2222-4222-8222-222222222222", COORD.agent_name),  # right name, other agent_id
    Pin(COORD.agent_id, "coord-main2"),                    # right agent_id, other name
    STRANGER,
])
def test_wrong_sender_is_ignored_never_answered(ctx, sender):
    d = validate_task(message(task_body(), sender=sender), ctx)
    assert (d.action, d.reason) == ("ignore", "sender")
    assert ctx.vault.calls == []


def test_sender_claimed_in_body_is_meaningless(ctx):
    body = task_body()
    body["agent_id"] = COORD.agent_id  # unknown key, and the bus sender is a stranger anyway
    d = validate_task(message(body, sender=STRANGER), ctx)
    assert (d.action, d.reason) == ("ignore", "sender")


def test_unpinned_coordinator_ignores_everything(ctx):
    ctx.coordinators = [Pin("", COORD.agent_name)]
    d = validate_task(message(task_body()), ctx)
    assert (d.action, d.reason) == ("ignore", "sender")


def test_task_must_be_kind_question(ctx):
    d = validate_task(message(task_body(), kind="announce"), ctx)
    assert (d.action, d.reason) == ("ignore", "kind")


# --- step 2: shape ------------------------------------------------------------------------------

@pytest.mark.parametrize("brief", [
    "tooling/other/x.txt", "docs/x.md", "x.txt", "/tooling/briefs/x.txt", "tooling/briefs/../secrets.txt",
    "tooling/briefs/a/../../x.txt", "tooling/briefs/..txt", "tooling/briefs/.hidden.txt", "tooling\\briefs\\x.txt",
    "tooling/briefs//x.txt", "tooling/briefs/x.ps1", "tooling/briefs/x.txt\n",
])
def test_brief_outside_briefs_or_with_dotdot_is_refused(ctx, brief):
    d = validate_task(message(task_body(brief=brief)), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", "brief")
    assert ctx.vault.calls == []


@pytest.mark.parametrize("commit", [COMMIT[:7], COMMIT[:39], COMMIT + "0", COMMIT.upper(), "main", "origin/main",
                                    "HEAD", "g" * 40, COMMIT[:39] + "\n", 12345])
def test_commit_not_40_lowercase_hex_is_refused(ctx, commit):
    d = validate_task(message(task_body(vault_commit=commit)), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", "vault_commit")


@pytest.mark.parametrize("branch", ["develop", "main", "master", "Main", "DEVELOP", "HEAD", "refs/heads/main",
                                    "origin/main", "a..b", "a/", "a.lock", "a//b", "feature/.x", "a@{1}", "-x",
                                    "a b", "a~1", "a^", "a:b"])
def test_protected_or_malformed_branch_is_refused(ctx, branch):
    d = validate_task(message(task_body(branch=branch)), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", "branch")


@pytest.mark.parametrize("model", ["claude-sonnet-4", "--allow-all-paths", "auto", "CLAUDE-OPUS-5.5", ""])
def test_model_not_in_allowlist_is_refused(ctx, model):
    d = validate_task(message(task_body(model=model)), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", "model")


def test_model_is_optional(ctx):
    assert validate_task(message(task_body(model=...)), ctx).accepted


@pytest.mark.parametrize("given,expected", [(..., True), (True, True), (False, False)])
def test_repo_instructions_is_an_optional_json_boolean_defaulting_to_load(ctx, given, expected):
    body = task_body() if given is ... else task_body(repo_instructions=given)
    d = validate_task(message(body), ctx)
    assert d.accepted and d.task["repo_instructions"] is expected


@pytest.mark.parametrize("over,field", [
    ({"repo": "evil-repo"}, "repo"), ({"worker": "con"}, "worker"), ({"worker": "a"}, "worker"),
    ({"worker": "host"}, "worker"),
    ({"host": "Alpha"}, "host"), ({"resume": "yes"}, "resume"), ({"resume": 1}, "resume"),
    ({"repo_instructions": "false"}, "repo_instructions"), ({"repo_instructions": 0}, "repo_instructions"),
    ({"repo_instructions": None}, "repo_instructions"),
    ({"needs": "sshdrop"}, "needs"), ({"needs": ["a"] * 9}, "needs"), ({"v": 2}, "v"), ({"v": True}, "v"),
    ({"extra": 1}, "unknown-key"), ({"task_id": "not-a-uuid"}, "task_id"),
])
def test_other_field_rules(ctx, over, field):
    d = validate_task(message(task_body(**over)), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", field)


def test_missing_field_is_refused(ctx):
    body = task_body()
    del body["branch"]
    d = validate_task(message(body), ctx)
    assert (d.action, d.field) == ("refuse", "branch")


@pytest.mark.parametrize("raw", ["not json", "[1,2]", '{"v":1,"type":"task","v":1}', "{\"v\": NaN}", "null"])
def test_body_that_is_not_one_json_object_is_refused(ctx, raw):
    d = validate_task(message(raw), ctx)
    assert (d.action, d.reason) == ("refuse", "shape")


def test_task_body_over_4kb_is_refused_before_anything_else(ctx):
    body = task_body()
    body["pad"] = "x" * MAX_BODY_BYTES
    d = validate_task(message(body), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "size", "size")
    assert ctx.vault.calls == []


def test_body_exactly_at_limit_is_measured_in_bytes(ctx):
    body = json.dumps(task_body())
    body = body[:-1] + "," + '"p":"' + "é" * ((MAX_BODY_BYTES - len(body)) // 2 + 1) + '"}'
    assert len(body) <= MAX_BODY_BYTES < len(body.encode())
    assert validate_task(message(body), ctx).reason == "size"


EXECUTABLE = ["; rm -rf /", "$(calc.exe)", "`calc`", "a && calc", "a || calc", "a | calc", "--allow-all-paths",
              "-c", "%COMSPEC%", "x\ncalc", "core14\n", "x'\"", "..\\..\\windows", "& calc", "> out.txt",
              "\u202ecore14", "core14 --flag", "a;b", "$env:PATH", "!cmd!"]
STRING_FIELDS = ["task_id", "host", "worker", "repo", "branch", "brief", "vault_commit", "model"]


@pytest.mark.parametrize("field", STRING_FIELDS + ["needs", "resume", "repo_instructions"])
@pytest.mark.parametrize("payload", EXECUTABLE)
def test_executable_looking_text_in_any_field_is_refused_and_reaches_no_shell(ctx, monkeypatch, field, payload):
    """Regression: every field is validated by pattern, so nothing a message says can reach a process."""
    spawned = []
    real_run = subprocess.run

    def spy_run(cmd, *a, **kw):
        spawned.append((cmd, kw.get("shell", False)))
        return real_run(cmd, *a, **kw)

    def forbid(*a, **kw):
        raise AssertionError("no shell or Popen may be used by validation")

    monkeypatch.setattr(subprocess, "run", spy_run)
    monkeypatch.setattr(subprocess, "Popen", forbid)
    monkeypatch.setattr(os, "system", forbid)
    value = [payload] if field == "needs" else payload
    d = validate_task(message(task_body(**{field: value})), ctx)
    assert d.action == "refuse" and d.reason == "shape" and d.field == field
    assert d.task is None
    # The refusal names the field only: the rejected value appears nowhere in it.
    assert payload not in json.dumps({"reason": d.reason, "field": d.field, "numbers": d.numbers, "digest": d.digest})
    for cmd, shell in spawned:
        assert shell is False and isinstance(cmd, list)
        assert payload not in cmd  # git check-ref-format only ever sees a branch that already passed its pattern
    assert ctx.vault.calls == []


def test_refusal_never_echoes_the_rejected_value(ctx):
    secretish = "feature/" + "x" * 20 + "..y"
    d = validate_task(message(task_body(branch=secretish)), ctx)
    assert d.action == "refuse"
    assert secretish not in repr((d.reason, d.field, d.numbers))


# --- targeting ----------------------------------------------------------------------------------

def test_other_host_and_missing_tags_are_ignored(ctx):
    assert validate_task(message(task_body(host="bravo")), ctx).reason == "other-host"
    assert validate_task(message(task_body(host="alpha")), ctx).accepted
    assert validate_task(message(task_body(needs=["labdata"])), ctx).reason == "tags"
    assert validate_task(message(task_body(needs=["sshdrop"])), ctx).accepted


# --- step 3: age and replay ---------------------------------------------------------------------

def test_seq_already_handled_is_ignored(ctx):
    ctx.handled_seqs = {100}
    assert validate_task(message(task_body(), seq=100), ctx).reason == "replay"


def test_old_task_is_refused_but_a_resume_skips_age(ctx):
    old = message(task_body(), created=NOW - timedelta(hours=3))
    d = validate_task(old, ctx)
    assert (d.action, d.reason) == ("refuse", "age")
    assert validate_task(old, ctx, resume=True).accepted


def test_future_dated_task_is_refused(ctx):
    d = validate_task(message(task_body(), created=NOW + timedelta(hours=1)), ctx)
    assert d.reason == "age"


def test_finished_task_id_is_refused(ctx):
    ctx.terminal_task_ids = {task_body()["task_id"]}
    d = validate_task(message(task_body()), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "replay", "task_id")


# --- step 4: vault ------------------------------------------------------------------------------

def test_commit_that_does_not_contain_the_brief_is_refused(ctx):
    ctx.vault = FakeVault(files={"tooling/briefs/other.txt": b"x"})
    d = validate_task(message(task_body()), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "brief", "brief")


def test_commit_not_on_main_is_refused(ctx):
    d = validate_task(message(task_body(vault_commit="0" * 40)), ctx)
    assert (d.action, d.reason) == ("refuse", "vault_commit")


def test_unknown_commit_is_refused(ctx):
    d = validate_task(message(task_body(vault_commit="1" * 40)), ctx)
    assert (d.action, d.reason) == ("refuse", "vault_commit")


def test_failed_fetch_refuses_no_stale_mirror(ctx):
    ctx.vault = FakeVault(fetch_ok=False)
    assert validate_task(message(task_body()), ctx).reason == "vault"


@pytest.mark.parametrize("entry", [("120000", "blob", b"target"), ("160000", "commit", b""),
                                   ("100755", "blob", b"x"), ("100644", "blob", b"x" * (24 * 1024 + 1)),
                                   ("100644", "blob", b"\xff\xfe bad utf8"), ("100644", "blob", b"a\x00b")])
def test_brief_must_be_a_small_regular_utf8_blob(ctx, entry):
    ctx.vault = FakeVault(files={BRIEF: entry})
    assert validate_task(message(task_body()), ctx).reason == "brief"


def test_brief_too_long_for_the_command_line_is_refused(ctx):
    seen = []
    ctx.fits_command_line = lambda text, policy=None: seen.append(policy) or False
    assert validate_task(message(task_body()), ctx).reason == "brief"
    assert seen and seen[0].project == "default"  # measured with the sending coordinator's own preamble


# --- steps 5 and 6 ------------------------------------------------------------------------------

def test_resources_refusal_carries_reason_and_host_numbers(ctx):
    ctx.resources = lambda: ("commit", {"commit_pct": 82.4, "limit": 80})
    d = validate_task(message(task_body()), ctx)
    assert (d.action, d.reason, d.numbers) == ("refuse", "commit", {"commit_pct": 82.4, "limit": 80})


def test_uniqueness_refusal(ctx):
    ctx.uniqueness = lambda worker, task_id: "busy"
    d = validate_task(message(task_body()), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "busy", "worker")


def test_steps_run_in_order(ctx):
    order = []
    ctx.vault.fetch = lambda: order.append("vault") or True
    ctx.resources = lambda: order.append("resources") or None
    ctx.uniqueness = lambda w, t: order.append("uniqueness") or None
    assert validate_task(message(task_body()), ctx).accepted
    assert order == ["vault", "resources", "uniqueness"]


# --- control messages ---------------------------------------------------------------------------

def test_control_messages(ctx):
    assert classify(message({"v": 1, "type": "cancel", "task": 100}), ctx)[0] == "cancel"
    assert classify(message({"v": 1, "type": "status"}), ctx)[0] == "status"
    assert classify(message({"v": 1, "type": "set-model", "model": "gpt-5.5"}), ctx)[0] == "set-model"
    assert classify(message({"v": 1, "type": "set-model", "model": "--yolo"}), ctx)[0] == "ignore"
    assert classify(message({"v": 1, "type": "shell", "cmd": "calc"}), ctx)[0] == "ignore"
    assert classify(message({"v": 1, "type": "stop"}), ctx)[0] == "ignore"  # no remote stop
    assert classify(message({"v": 1, "type": "status"}, sender=STRANGER), ctx)[0] == "ignore"
