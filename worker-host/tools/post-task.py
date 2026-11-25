"""Post one task to the worker hosts, as a coordinator, and (optionally) follow it to the end.

docs/coordinator-guide.md is the manual; this is the mechanical part, so no coordinator hand-writes the JSON:

  python tools/post-task.py --as <your agent name> --channel worker-hosts \\
      --repo https://github.com/<owner>/<repo> --branch feature/x --worker core14 \\
      --brief tooling/briefs/x.md --commit <40-hex on your notes repo's main> [--follow]

Options: --host <name|any> (default any), --model <id>, --repo-instructions true|false, --needs <tag> (repeat),
--resume, --follow-minutes <n> (default 30 with --follow), --dry-run (print the task, post nothing).

The task is checked with the hosts' own field rules (workerhost/validate.py) before anything is posted, so a typo
comes back here, not as a refusal on the bus. What only a host can check (your fleet.toml entry, the brief at that
commit, resources) still comes back as a reply; --follow prints every reply until the task ends.

Credentials: your bus identity in a DPAPI store, as the hosts and workers keep theirs. --store <folder>, else
SB_BUS_STORE. The bus and its CA: --bus/--ca, else SB_BUS_URL/SB_BUS_CA;
the bus also falls back to the one your identity was made on. Nothing secret is ever printed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workerhost import creds, urls  # noqa: E402
from workerhost.busclient import Bus, BusError, setting  # noqa: E402
from workerhost.validate import Context, Policy, ShapeError, check_task_fields, resolve_repo  # noqa: E402

TERMINAL = {"finished", "failed", "timed-out", "interrupted"}


class _NoVault:
    def __getattr__(self, name):
        raise AssertionError("post-task never reads a notes repository")


def build_task(args) -> dict:
    task = {"v": 1, "type": "task", "task_id": args.task_id or str(uuid.uuid4()), "host": args.host,
            "worker": args.worker, "repo": args.repo, "branch": args.branch, "brief": args.brief,
            "vault_commit": args.commit}
    if args.model:
        task["model"] = args.model
    if args.repo_instructions is not None:
        task["repo_instructions"] = args.repo_instructions == "true"
    if args.needs:
        task["needs"] = list(args.needs)
    if args.resume:
        task["resume"] = True
    return task


def check(task: dict, models: list[str]) -> str | None:
    """The hosts' own field rules. Returns the failing field, or None. The repository is checked against the
    hosts' default [remotes] fence; your own fleet.toml `repos` is checked by the hosts."""
    ctx = Context(host_name="any", coordinators=[], repos={}, allowed_models=models, tags=[], vault=_NoVault())
    policy = Policy(vault=_NoVault(), repos=tuple(urls.DEFAULT_REMOTES), legacy=False)
    try:
        check_task_fields(task, ctx, git_check=False, policy=policy)
        resolve_repo(task["repo"], ctx, policy)
    except ShapeError as e:
        return e.field
    return None


def summarise(m: dict) -> str:
    try:
        body = json.loads(m.get("body") or "{}")
    except ValueError:
        body = {}
    kind = body.get("type", "?")
    keep = ("reason", "field", "worker", "model", "project", "exit_code", "minutes", "pushed", "wip_branch", "aic",
            "repo_instructions", "outcome")
    extra = " ".join(f"{k}={body[k]}" for k in keep if k in body)
    return f"[{m['seq']}] {str(m.get('created_at'))[11:19]} {m.get('agent_name')}: {kind} {extra}".rstrip()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Post a task to the strugglebus worker hosts.")
    p.add_argument("--as", dest="agent", required=True, help="your coordinator agent name (in fleet.toml)")
    p.add_argument("--channel", required=True, help="the hosts' channel, e.g. worker-hosts or worker-hosts-test")
    p.add_argument("--repo", required=True, help="full clone URL, https://<host>/<owner>/<repo>")
    p.add_argument("--branch", required=True)
    p.add_argument("--worker", required=True, help="short worker name, e.g. core14 (one clone per name per host)")
    p.add_argument("--brief", required=True, help="tooling/briefs/<name>.md|.txt in your notes repository")
    p.add_argument("--commit", required=True, help="40-hex commit on your notes repository's main holding the brief")
    p.add_argument("--host", default="any")
    p.add_argument("--model", default="")
    p.add_argument("--models", default="claude-opus-5.5,gpt-5.5", help="models the hosts allow (local check only)")
    p.add_argument("--repo-instructions", choices=("true", "false"), default=None)
    p.add_argument("--needs", action="append", default=[])
    p.add_argument("--resume", action="store_true")
    p.add_argument("--task-id", default="", help="re-post after a failed claim keeps its task_id; default: new")
    p.add_argument("--store", default="")
    p.add_argument("--bus", default="")
    p.add_argument("--ca", default="")
    p.add_argument("--follow", action="store_true")
    p.add_argument("--follow-minutes", type=float, default=30.0)
    p.add_argument("--dry-run", action="store_true")
    return p


def connect(args) -> Bus | str:
    """A bus client as your identity, or the reason there is none (printed by main)."""
    store = args.store or setting("BUS_STORE")
    if not store:
        return "no credential store: --store, or SB_BUS_STORE"
    try:
        record = creds.Store(Path(store)).load(args.agent)
    except (OSError, LookupError, ValueError, KeyError):
        return f"no identity {args.agent} in that store"
    base, ca = args.bus or setting("BUS_URL") or record.get("base_url"), args.ca or setting("BUS_CA")
    if not base or not ca:
        return "which bus? --bus and --ca, or SB_BUS_URL and SB_BUS_CA"
    return Bus(base, ca, record["secret"])


def follow(bus, channel: str, seq: int, minutes: float, sleep=time.sleep) -> int:
    """Print the hosts' replies to the task until a terminal one: 0 for finished, 1 for any other end. Past the time
    limit: 0 if a host started it, else 1."""
    end, seen, claimed = time.time() + 60 * minutes, set(), False
    while time.time() < end:
        try:
            msgs = bus.read(channel, seq, 100)
        except (BusError, OSError, ValueError):
            msgs = []
        for m in msgs:
            if m["seq"] in seen or m.get("reply_to") != seq:
                continue
            seen.add(m["seq"])
            print(summarise(m), flush=True)
            kind = json.loads(m.get("body") or "{}").get("type") if m.get("body", "").startswith("{") else None
            claimed = claimed or kind == "started"
            if kind in TERMINAL:
                return 0 if kind == "finished" else 1
        sleep(10)
    print("post-task: stopped following (the task may still be running; its replies stay on the channel)")
    return 0 if claimed else 1


def main(argv: list[str]) -> int:
    args = parser().parse_args(argv)
    task = build_task(args)
    bad = check(task, [m for m in args.models.split(",") if m])
    if bad:
        print(f"post-task: the hosts would refuse this task: field {bad} (see docs/coordinator-guide.md)")
        return 2
    task["repo"] = urls.canonical(task["repo"]) or task["repo"]
    body = json.dumps(task, separators=(",", ":"))
    if args.dry_run:
        print(body)
        return 0
    bus = connect(args)
    if isinstance(bus, str):
        print(f"post-task: {bus}")
        return 2
    try:
        seq = bus.post(args.channel, "question", body)
    except BusError as e:
        print(f"post-task: the bus refused the post (HTTP {e.status})")
        return 1
    print(f"posted task {task['task_id']} as seq {seq} on {args.channel}")
    return follow(bus, args.channel, seq, args.follow_minutes) if args.follow else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
