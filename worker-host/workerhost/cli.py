"""`wh`: the commands the host's owner runs (design section 7).

  wh start | stop | drain | pause | resume | status [--post] | set-model <model>
  wh cleanup [--dry-run] | update-ghcp [--when-idle] | enrol [...] | probe | run | supervise

Local commands reach a running host through control files in the owner-only state folder; with no
host running they change state.json directly (under its lock). Nothing here talks to the bus except
`enrol`, `probe` and `status --post` (which asks the host to post).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import config as config_mod
from . import creds, ghcp, panel, signing, winapi
from . import fleet as fleet_mod
from .busclient import Bus, BusError, bootstrap, onboard
from .host import Host, load_pins, save_pins
from .hostevents import EventLog
from .logs import HostLog
from .state import StateStore, send_control
from .supervisor import Supervisor
from .validate import UUID_RE, Pin


def _schtasks(cfg, *args: str) -> int:
    if not cfg.scheduled_task or not winapi.IS_WINDOWS:
        return 0
    r = subprocess.run(["schtasks", *args, "/TN", cfg.scheduled_task], capture_output=True, stdin=subprocess.DEVNULL)
    return r.returncode


def host_status(cfg) -> dict | None:
    """status.json if the host process that wrote it is alive."""
    try:
        status = json.loads((cfg.state_dir / "status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    pid = int(status.get("pid") or 0)
    # pid_alive, not process_identity: from the signed-in session the host's process (session 0) can't be opened.
    if not pid or not winapi.pid_alive(pid) or time.time() - status.get("updated", 0) > 120:
        return None
    return status


def _wait_until(pred, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(1)
    return pred()


def cmd_start(cfg, args) -> int:
    StateStore(cfg.state_dir).update(lambda d: d.update(enabled=True, draining=False))
    if host_status(cfg):
        print("host already running")
        return 0
    if cfg.scheduled_task:
        _schtasks(cfg, "/Change", "/ENABLE")
        code = _schtasks(cfg, "/Run")
        print("scheduled task enabled and started" if code == 0 else f"could not start the scheduled task ({code})")
        return code
    py = cfg.python_exe or sys.executable
    flags = winapi.DETACHED_PROCESS | winapi.CREATE_NEW_PROCESS_GROUP if winapi.IS_WINDOWS else 0
    subprocess.Popen([py, str(config_mod.INSTALL_DIR / "wh.py"), "--home", str(cfg.home), "supervise"],
                     cwd=str(config_mod.INSTALL_DIR), creationflags=flags, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("host started (no scheduled task configured)")
    return 0


def cmd_stop(cfg, args) -> int:
    status = host_status(cfg)
    if status:
        send_control(cfg.control_dir, "stop")
        if not _wait_until(lambda: host_status(cfg) is None, 30):
            # recorded before the kill as well as after it: a save by the dying host can briefly restore
            # enabled=true, but the write below lands before the supervisor's first backoff (10 s) ends,
            # and the supervisor checks the flag throughout that wait, so a stopped host is not restarted
            StateStore(cfg.state_dir).update(lambda d: d.update(enabled=False, draining=False))
            winapi.terminate_pid(int(status["pid"]))
            print("host did not stop within 30 s: process killed (its workers die with it)")
    StateStore(cfg.state_dir).update(lambda d: d.update(enabled=False, draining=False))
    _schtasks(cfg, "/End")
    _schtasks(cfg, "/Change", "/DISABLE")
    print("stopped; the host will not come back after a reboot until `wh start`")
    return 0


def _flag(cfg, cmd: str, **state_changes) -> int:
    if host_status(cfg):
        send_control(cfg.control_dir, cmd)
        print(f"{cmd}: sent to the running host")
    else:
        StateStore(cfg.state_dir).update(lambda d: d.update(**state_changes))
        print(f"{cmd}: host not running; recorded for its next start")
    return 0


def cmd_drain(cfg, args) -> int:
    if not host_status(cfg):
        StateStore(cfg.state_dir).update(lambda d: d.update(enabled=False, draining=False))
        _schtasks(cfg, "/Change", "/DISABLE")
        print("drain: host not running; disabled")
        return 0
    send_control(cfg.control_dir, "drain")
    print("drain: no new claims; the host stops and disables itself when its workers finish")
    return 0


def cmd_pause(cfg, args) -> int:
    return _flag(cfg, "pause", paused=True)


def cmd_resume(cfg, args) -> int:
    return _flag(cfg, "resume", paused=False)


def cmd_status(cfg, args) -> int:
    status = host_status(cfg)
    st = StateStore(cfg.state_dir).load()
    task = cfg.scheduled_task or "none"
    if status is None:
        print(f"host not running (enabled={st['enabled']} paused={st['paused']} draining={st['draining']} "
              f"logon={cfg.logon_type} task={task})")
        return 1
    if args.post:
        send_control(cfg.control_dir, "status")
    print(status["heartbeat_line"])
    print(f"channel={status['channel']} ({status['channel_state']}) bus={status['bus_state']} "
          f"paused={status['paused']} game_paused={status['game_paused']} outbox={status['outbox']} "
          f"logon={cfg.logon_type} task={task}")
    for w in status["workers"]:
        print(f"  {w['worker']:<20} task={w['task_id']} model={w['model']} {w['minutes']} min  log={w['log']}")
    if status["held_clones"]:
        reasons = status.get("held_reasons") or {}
        print("  held clones: " + ", ".join(f"{w} ({reasons[w]})" if w in reasons else w
                                            for w in status["held_clones"]))
    fl = status.get("fleet")
    if fl:
        print(f"  fleet: {fl.get('label') or fl.get('state')}  coordinators: {', '.join(fl.get('coordinators', [])) or 'NONE'}"
              f"  hosts: {', '.join(fl.get('hosts', []))}  (wh fleet status for the signers)")
    if status.get("strays"):
        print("  not clones (no .git; never deleted by the host, check and delete by hand): "
              + ", ".join(status["strays"]))
    return 0


def cmd_set_model(cfg, args) -> int:
    from .models import is_allowed
    if not is_allowed(args.model, cfg.allowed_models, cfg.denied_models):
        print("that model does not match models.allowed (or matches models.denied)")
        return 2
    if host_status(cfg):
        send_control(cfg.control_dir, "set-model", model=args.model)
        print("set-model: sent to the running host")
        return 0
    return _flag(cfg, "set-model", default_model=args.model)


def cmd_cleanup(cfg, args) -> int:
    if host_status(cfg) and not args.dry_run:
        send_control(cfg.control_dir, "cleanup")
        print("cleanup: sent to the running host (see the host log)")
        return 0
    host = Host(cfg)
    running = bool(host_status(cfg))
    # With no host running nothing waits on the sweep, so it has no time budget: it clears a backlog in one go.
    report = host.run_cleanup(dry_run=True if running else args.dry_run, budget=running)
    for key in ("deleted", "would_delete", "held", "failed"):
        for item in report[key]:
            print(f"{key}: {item}")
    for name in report["strays"]:
        print(f"stray: {name} (no .git; not deleted)")
    print(f"clones on disk: {report['clones']}")
    if report["deferred"]:
        print(f"deferred to the next sweep (time budget): {report['deferred']}")
    return 0


def cmd_update_ghcp(cfg, args) -> int:
    status = host_status(cfg)
    if status:
        if status["workers"] and not args.when_idle:
            print("workers are running; use --when-idle to update after they finish")
            return 1
        send_control(cfg.control_dir, "update-ghcp", when_idle=bool(args.when_idle))
        print("update-ghcp: sent to the running host")
        return 0
    result = ghcp.update(cfg.copilot_exe, cfg.ghcp_backup_dir, cfg.ghcp.winget_id)
    print(result.line)
    return 0 if result.ok else 1


def _lookup_coordinator(bus: Bus, name: str, channels: tuple[str, ...]) -> set[str]:
    """The agent_ids that posted as `name` in the last 1,000 messages of each channel."""
    ids = set()
    for channel in channels:
        try:
            newest = bus.newest_seq(channel)
            for m in bus.read_all(channel, max(0, newest - 1000)):
                if m.get("agent_name") == name and isinstance(m.get("agent_id"), str):
                    ids.add(m["agent_id"])
        except (BusError, OSError, ValueError):
            pass
    return ids


def _enrol_with_code(cfg, store, where: str) -> int:
    """`wh enrol --code-stdin`: redeem the App's one-time host enrolment code for this host's own service principal,
    onboard <prefix>-host, and print the M1 confirmation code (docs/app-host-integration.md section 2.2 step 8)."""
    from . import hostenrol

    if store.has(cfg.host_agent):
        print(f"enrol: {cfg.host_agent} already has a credential; refusing to re-enrol")
        return 1
    code = sys.stdin.readline().strip()
    rid = hostenrol.request_id(cfg.state_dir)
    try:
        spn = hostenrol.redeem(Bus(cfg.bus_url, cfg.bus_ca), code, rid, cfg.agent_prefix)
    except hostenrol.EnrolError as e:
        print(f"enrol: {e}")
        return 1
    except (OSError, ValueError) as e:
        print(f"enrol: could not reach the bus ({type(e).__name__}); run it again: the code works for 15 minutes")
        return 1
    del code
    store.save_spn(spn)
    try:
        record = onboard(Bus(cfg.bus_url, cfg.bus_ca), spn, cfg.host_agent, "strugglebus worker host")
    except BusError as e:
        print(f"enrol: onboarding refused by the bus (HTTP {e.status}); run it again within 15 minutes")
        return 1
    except (OSError, ValueError, KeyError) as e:
        print(f"enrol: could not reach the bus ({type(e).__name__}); run it again within 15 minutes")
        return 1
    del spn
    store.save(cfg.host_agent, record)
    print(f"enrol: host identity {record['agent_name']} ({record['agent_id']}) stored {where}")
    try:
        for note in bootstrap(Bus(cfg.bus_url, cfg.bus_ca, record["secret"]), record, (cfg.channel,)):
            print("  " + note)
    except (BusError, OSError, KeyError) as e:
        print(f"  bootstrap incomplete ({getattr(e, 'status', type(e).__name__)}); the host retries on start")
    save_pins(cfg, host=Pin(record["agent_id"], record["agent_name"]))
    print(f"enrol: CONFIRMATION CODE {hostenrol.confirmation_code(record['agent_id'], rid)}: compare it with the "
          "code the App shows before you approve this host into the fleet")
    return 0


def cmd_enrol(cfg, args) -> int:
    store = _openbao_store(cfg) if cfg.openbao.enabled else creds.Store(cfg.creds_dir)
    where = "in OpenBao" if cfg.openbao.enabled else "with DPAPI"
    if getattr(args, "code_stdin", False):
        return _enrol_with_code(cfg, store, where)
    if args.import_identity:
        try:
            record = json.loads(Path(args.import_identity).read_text(encoding="utf-8"))
            record = {k: record[k] for k in ("agent_id", "agent_name", "secret") if k in record} | {
                "base_url": cfg.bus_url}
            if set(record) != {"agent_id", "agent_name", "secret", "base_url"}:
                raise ValueError
        except (OSError, ValueError, KeyError):
            print("enrol: that file is not a bus identity record")
            return 1
        store.save(cfg.host_agent, record)
        print(f"enrol: adopted identity {record['agent_name']} ({record['agent_id']}) for this host")
    else:
        if store.has(cfg.host_agent):
            print(f"enrol: {cfg.host_agent} already has a credential; refusing to re-enrol")
            return 1
        if cfg.openbao.enabled and store.has_spn():
            spn = store.load_spn()  # seeded once with `wh openbao seed-spn`; nobody types it again
        else:
            spn = (sys.stdin.readline() if args.spn_stdin else getpass.getpass("SPN credential (input hidden): ")).strip()
            if not spn.startswith("sbsp1_") or len(spn) < 20:
                print("enrol: that does not look like an SPN credential (expected sbsp1_...); nothing stored")
                return 1
            store.save_spn(spn)
        try:
            record = onboard(Bus(cfg.bus_url, cfg.bus_ca), spn, cfg.host_agent, "strugglebus worker host")
        except BusError as e:
            (cfg.creds_dir / "spn.bin").unlink(missing_ok=True)
            print(f"enrol: onboarding refused by the bus (HTTP {e.status}); nothing stored, nothing printed")
            if e.detail:
                print(f"enrol: the bus says: {e.detail}")
            if 400 <= e.status < 500:
                print(f"enrol: agent_prefix in config.toml must equal the SPN's name "
                      f"(this host asked for {cfg.host_agent})")
            return 1
        except (OSError, ValueError, KeyError) as e:
            (cfg.creds_dir / "spn.bin").unlink(missing_ok=True)
            print(f"enrol: could not reach the bus ({type(e).__name__}); nothing stored")
            return 1
        store.save(cfg.host_agent, record)
        print(f"enrol: host identity {record['agent_name']} ({record['agent_id']}) stored {where}")
    bus = Bus(cfg.bus_url, cfg.bus_ca, record["secret"])
    try:
        for note in bootstrap(bus, record, (cfg.channel,)):
            print("  " + note)
    except (BusError, OSError, KeyError) as e:
        print(f"  bootstrap incomplete ({getattr(e, 'status', type(e).__name__)}); the host retries on start")
    save_pins(cfg, host=Pin(record["agent_id"], record["agent_name"]))
    coord = args.coordinator_id
    if not coord:
        found = _lookup_coordinator(bus, cfg.coordinator_name, (cfg.channel, "announce"))  # where it posts tasks
        if len(found) == 1:
            coord = next(iter(found))
            answer = input(f"pin {cfg.coordinator_name} as agent_id {coord}? [y/N] ").strip().lower()
            coord = coord if answer == "y" else None
    if coord and UUID_RE.fullmatch(coord):
        save_pins(cfg, coordinator=Pin(coord, cfg.coordinator_name))
        print(f"enrol: coordinator pinned: {cfg.coordinator_name} {coord}")
    else:
        print("enrol: coordinator NOT pinned; every task is ignored until `wh enrol --coordinator-id <id>`")
    print(f"add this host to the other hosts' config: [[hosts]] agent_name = \"{record['agent_name']}\" "
          f"agent_id = \"{record['agent_id']}\"")
    print("once fleet.toml is in use: `wh fleet entry --host` prints this host's entry for a fleet.toml PR")
    return 0


def cmd_pin(cfg, args) -> int:
    if not UUID_RE.fullmatch(args.coordinator_id or ""):
        print("pin: --coordinator-id must be a lower-case UUID")
        return 2
    save_pins(cfg, coordinator=Pin(args.coordinator_id, cfg.coordinator_name))
    print(f"coordinator pinned: {cfg.coordinator_name} {args.coordinator_id}")
    return 0


def _fleet_sync(cfg) -> fleet_mod.FleetSync:
    return fleet_mod.FleetSync(cfg.fleet_mirror_dir, cfg.fleet_store_dir, cfg.fleet_remote(), cfg.git_exe,
                               signing.find_ssh_keygen(cfg.ssh_keygen_exe), signing.pinned_path())


def _host_bus(cfg) -> Bus | None:
    """A bus client as this host's own agent (what reads the fleet from the bus), or None without a credential."""
    try:
        store = _openbao_store(cfg) if cfg.openbao.enabled else creds.Store(cfg.creds_dir)
        return Bus(cfg.bus_url, cfg.bus_ca, store.load(cfg.host_agent)["secret"])
    except (LookupError, OSError, ValueError, KeyError):
        return None


def signer_lines(cfg) -> list[str]:
    path = signing.pinned_path()
    signers = signing.read_signers(path)
    if not signers:
        return [f"pinned signers: NONE at {path} (run install.ps1 -PinSigners in an elevated PowerShell)"]
    return [f"pinned signers ({path}):"] + [f"  {s.fingerprint}  {s.comment}  [{s.namespaces}]" for s in signers]


def cmd_fleet_status(cfg, args) -> int:
    for line in signer_lines(cfg):
        print(line)
    print(f"ssh-keygen: {signing.find_ssh_keygen(cfg.ssh_keygen_exe) or 'NOT FOUND'}")
    sync = _fleet_sync(cfg)
    if args.refresh:
        if host_status(cfg):
            send_control(cfg.control_dir, "fleet-refresh")
            print("fleet-refresh: sent to the running host (the result is in the host log and the next heartbeat)")
        else:
            bus = _host_bus(cfg) if cfg.fleet_source != "git" else None
            out = sync.refresh(sync.load_last_good(), bus=bus, source=cfg.fleet_source)
            print(f"refresh ({cfg.fleet_source}): {out.status} commit={out.commit[:12] or '-'} {out.detail}")
    kept = sync.load_last_good()
    if kept is None:
        state = "UNAVAILABLE: a fleet was accepted before but the kept copy does not verify; this host trusts " \
                "nobody until a refresh succeeds" if sync.accepted() else \
                "none accepted yet: config.toml [coordinator] and [[hosts]] are in use"
        print(f"fleet: {state}")
        return 0
    print(f"fleet: serial {kept.serial}, commit {kept.commit[:12]}, signed by {sync.accepted().get('signer', '?')}")
    for c in kept.coordinators:
        print(f"  coordinator {c.agent_name:<28} project={c.project} engine={c.default_engine} "
              f"notes={c.notes_repo} channel={c.notes_channel}")
        print(f"    repos: {', '.join(c.repos)}")
        rules = f"{len(c.worker_rules.splitlines())} line(s)" if c.worker_rules else "none"
        print(f"    repo_instructions default: {'load' if c.repo_instructions else 'off'}; worker rules: {rules}")
    for h in kept.hosts:
        print(f"  host        {h.agent_name:<28} {h.agent_id}")
    if kept.ignored_keys:
        print(f"  ignored (newer than this host): {', '.join(kept.ignored_keys)}")
    return 0


def _toml_str(value: str) -> str:
    return json.dumps(value)  # a JSON string is a valid TOML basic string


def cmd_fleet_entry(cfg, args) -> int:
    """Print a fleet.toml entry to paste into a PR (it changes nothing here)."""
    if args.host:
        me = load_pins(cfg)["host"]
        if not me.agent_id:
            print("this host has no bus identity yet: run wh enrol first")
            return 1
        text = f"[[host]]\nagent_name = {_toml_str(me.agent_name)}\nagent_id   = {_toml_str(me.agent_id)}\n"
    else:
        if not (args.coordinator and args.project and args.notes_repo and args.notes_channel and args.repos):
            print("wh fleet entry --coordinator <name> --project <p> --notes-repo <url> --notes-channel <channel> "
                  "--repos <url-prefix> [...] [--engine ghcp|claude] [--agent-id <uuid>]")
            return 2
        agent_id = args.agent_id
        if not agent_id:
            try:
                rec = creds.Store(cfg.creds_dir).load(cfg.host_agent)
                bus = Bus(cfg.bus_url, cfg.bus_ca, rec["secret"])
            except (LookupError, OSError, ValueError, KeyError):
                print("no host credential to look the coordinator up with: pass --agent-id")
                return 1
            found = _lookup_coordinator(bus, args.coordinator, (args.notes_channel, "announce", cfg.channel))
            if len(found) != 1:
                print(f"found {len(found)} agent_ids for {args.coordinator} on the bus: pass --agent-id")
                return 1
            agent_id = next(iter(found))
        repos = ", ".join(_toml_str(r) for r in args.repos)
        text = (f"[[coordinator]]\nagent_name     = {_toml_str(args.coordinator)}\nagent_id       = "
                f"{_toml_str(agent_id)}\nproject        = {_toml_str(args.project)}\nnotes_repo     = "
                f"{_toml_str(args.notes_repo)}\nnotes_channel  = {_toml_str(args.notes_channel)}\n"
                f"repos          = [{repos}]\ndefault_engine = {_toml_str(args.engine)}\n")
    try:
        fleet_mod.parse(b"serial = 1\n\n" + text.encode())
    except fleet_mod.FleetError as e:
        print(f"that entry would not be valid: {e.detail}")
        return 1
    print(text, end="")
    return 0


def _probe_engines(cfg, check, lines: list[str]) -> None:
    """The default engine must work; the other is information. A Claude-only host passes without Copilot CLI."""
    from . import engines as engines_mod

    copilot = ghcp.version(cfg.copilot_exe)
    if cfg.default_engine == "ghcp":
        check(f"copilot --version ({copilot or '?'})", copilot is not None)
    else:
        lines.append(f"info copilot --version: {copilot or 'not installed'}")
    if cfg.claude is None:
        return
    installed = bool(engines_mod.resolve(cfg.claude.exe))
    signed_in = engines_mod.claude_signed_in()
    label = f"claude installed ({'yes' if installed else 'no'}) and signed in ({'yes' if signed_in else 'no'})"
    if cfg.default_engine == "claude":
        check(label, installed and signed_in)
    else:
        lines.append(f"info {label}")


def cmd_probe(cfg, args) -> int:
    lines, ok = [], True

    def check(name: str, passed: bool):
        nonlocal ok
        ok &= passed
        lines.append(f"{'ok  ' if passed else 'FAIL'} {name}")

    def runs(cmd: list[str]) -> bool:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=120, stdin=subprocess.DEVNULL).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    check("bus_url set (site.toml, install.ps1 -SiteFile)", bool(cfg.bus_url))
    if not cfg.fleet_remote() and cfg.fleet_source == "git":
        lines.append("info fleet_repo: none, so no signed fleet and no self-update; config.toml's [coordinator] pin only")
    elif not cfg.fleet_remote():
        lines.append(f"info fleet_source {cfg.fleet_source}: the signed fleet comes from the bus; no fleet_repo, so no "
                     "self-update yet")
    _probe_engines(cfg, check, lines)
    check("gh auth status", runs([cfg.gh_exe, "auth", "status"]))
    if cfg.vault_remote():
        check("git ls-remote of the vault", runs([cfg.git_exe, "ls-remote", "--heads", "--", cfg.vault_remote(), "main"]))
    check("bus CA file", bool(cfg.bus_ca) and Path(cfg.bus_ca).is_file())
    check("workers root reachable", Path(cfg.workers_root).anchor == "" or Path(Path(cfg.workers_root).anchor).exists())
    try:
        winapi.dpapi_unprotect(winapi.dpapi_protect(b"probe"))
        check("DPAPI (user profile loaded)", True)
    except OSError:
        check("DPAPI (user profile loaded)", False)
    pins = load_pins(cfg)
    if cfg.openbao.enabled:
        try:
            ident = "yes (OpenBao)" if _openbao_store(cfg).has(cfg.host_agent) else "no (wh openbao migrate, or wh enrol)"
        except OSError as e:
            ident = f"unknown: OpenBao {getattr(e, 'what', type(e).__name__)} (wh openbao status)"
    else:
        ident = "yes" if creds.Store(cfg.creds_dir).has(cfg.host_agent) else "no (run wh enrol)"
    lines.append(f"info coordinator pinned: {'yes' if pins['coordinator'].agent_id else 'no'}; host identity: {ident}")
    # Information, not a failure: before the first signed fleet.toml a host runs on config.toml's pins.
    signers = signing.read_signers(signing.pinned_path())
    lines.append(f"info signers pinned: {len(signers) or 'none (install.ps1 -PinSigners, elevated)'}; "
                 f"ssh-keygen: {signing.find_ssh_keygen(cfg.ssh_keygen_exe) or 'not found'}")
    try:
        import tkinter  # noqa: F401
        lines.append("info status window (wh panel): available")
    except ImportError:
        lines.append("info status window (wh panel): tkinter missing; reinstall Python with 'tcl/tk and IDLE'")
    text = "\n".join(lines)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0 if ok else 1


def cmd_run(cfg, args) -> int:
    try:
        host = Host(cfg, echo=args.echo)
    except BaseException as e:  # noqa: BLE001 - logged, then re-raised: never a silent exit
        HostLog(cfg.logs_dir).error("fatal", e)
        raise
    return host.run(max_seconds=args.max_seconds)


def cmd_selftest(cfg, args) -> int:
    """Run by self-update on a STAGED release (python <home>\\app.new\\wh.py --home <home> selftest) before it is put
    in place: every module of this code imports, this host's config.toml loads with it, and the kept fleet.toml still
    parses. Nothing is changed and nothing is fetched."""
    import importlib
    import pkgutil

    import workerhost

    for mod in pkgutil.iter_modules(workerhost.__path__):
        importlib.import_module(f"workerhost.{mod.name}")
    kept = cfg.fleet_store_dir / fleet_mod.FILE
    if kept.exists():
        fleet_mod.parse(kept.read_bytes())
    print(f"selftest ok: {len(list(pkgutil.iter_modules(workerhost.__path__)))} modules, config loads, "
          f"code at {Path(workerhost.__file__).parent}")
    return 0


def cmd_update(cfg, args) -> int:
    from . import update as update_mod

    which = getattr(args, "update_cmd", None) or "status"
    inst = update_mod.installed(config_mod.INSTALL_DIR)
    st = update_mod.load_state(cfg.state_dir / "update.json")
    if which == "status":
        u = cfg.update
        print(f"installed: {inst['version']} (release serial {inst['serial']}, commit {inst['commit'][:12] or '-'})")
        print(f"window: check {u.check_at}, apply {u.window}, grace {u.grace_minutes:g} min, "
              f"announce on {u.announce_channel}; {'enabled' if u.enabled else 'DISABLED'}")
        phase = st.get("phase") or "none"
        print(f"update: {phase}" + (f" {st.get('from_version', '?')} -> {st.get('version', '?')}" if st.get("version") else ""))
        if st.get("rejected"):
            print(f"never retried (failed or rolled back here): serial {', '.join(map(str, st['rejected']))}")
        return 0
    if host_status(cfg):
        send_control(cfg.control_dir, "update-check" if which == "check" else "update-now")
        print(f"update-{which}: sent to the running host (the result is in the host log, the heartbeat and, for "
              f"'now', the announce channel)")
        return 0
    if which == "now":
        print("update now: the host is not running; start it (wh start), then run this again")
        return 1
    w = update_mod.where(cfg, inst)
    if w.origin == "fleet":
        sync = _fleet_sync(cfg)
        fetched = sync.refresh(sync.load_last_good()).status  # fetches the mirror
        mirror = cfg.fleet_mirror_dir
    else:
        mirror = update_mod.mirror_for(cfg.release_mirrors_dir, w.url)
        fetched = "ok" if update_mod.fetch_release_mirror(cfg.git_exe, mirror, w.url) else "release-source-unreachable"
    src = update_mod.ReleaseSource(mirror, cfg.git_exe, signing.find_ssh_keygen(cfg.ssh_keygen_exe),
                                   signing.pinned_path(), cfg.state_dir / "release-tmp", path=w.path)
    rel, status = src.read()
    if rel is None:
        print(f"release ({w.label()}): {status} (fetch: {fetched})")
        return 1
    newer = update_mod.is_newer(rel, inst)
    print(f"release: {rel.version} (serial {rel.serial}, commit {rel.commit[:12]}), signed; installed {inst['version']}; "
          f"{'NEWER: it is applied in the next window' if newer else 'nothing to do'}"
          + (" (needs install.ps1 by hand)" if rel.needs_install else ""))
    return 0


def _openbao_store(cfg):
    from . import openbao
    from .host import openbao_client

    return openbao.Store(openbao_client(cfg), cfg.host_agent)


def _hidden(prompt: str, from_stdin: bool) -> str:
    return (sys.stdin.readline() if from_stdin else getpass.getpass(prompt)).strip()


def cmd_openbao(cfg, args) -> int:
    """docs/openbao-design.md section 2.5. Secrets are read at a hidden prompt (or one stdin line), never echoed,
    never on a command line; errors show the HTTP status and a fixed label only."""
    from . import openbao

    which = getattr(args, "openbao_cmd", None) or "status"
    ob, leaf = cfg.openbao, cfg.leaf_dir
    ca = ob.ca or cfg.bus_ca
    try:
        if which == "enrol":
            csr = Path(args.csr) if args.csr else leaf / openbao.LEAF_CSR
            if not (leaf / openbao.LEAF_KEY).is_file() or not csr.is_file():
                print(f"enrol: no key and CSR in {leaf}; run setup\\30-openbao.ps1 (it makes them, then calls this)")
                return 1
            token = _hidden("one-time step-ca token (input hidden): ", args.token_stdin)
            if token.count(".") != 2:
                print("enrol: that does not look like a step-ca one-time token (a JWT); nothing sent")
                return 1
            chain = openbao.sign_leaf(ob.ca_url, ca, csr.read_text(encoding="ascii"), token, f"{ob.leaf_hours}h")
            del token
            openbao.write_leaf(leaf, chain)
            csr.unlink(missing_ok=True)
            left = (openbao.leaf_not_after(leaf / openbao.LEAF_CRT) or time.time()) - time.time()
            print(f"enrol: leaf {', '.join(openbao.leaf_san(leaf / openbao.LEAF_CRT))} issued, "
                  f"{left / 3600:.0f} h left; the host renews it hourly")
            return 0
        if which == "renew":
            chain = openbao.renew_leaf(ob.ca_url, ca, leaf)
            openbao.write_leaf(leaf, chain)
            left = (openbao.leaf_not_after(leaf / openbao.LEAF_CRT) or time.time()) - time.time()
            print(f"renew: done, {left / 3600:.0f} h left")
            return 0
        store = _openbao_store(cfg)
        if which == "seed-spn":
            spn = _hidden("SPN credential (input hidden): ", args.spn_stdin)
            if not spn.startswith("sbsp1_") or len(spn) < 20:
                print("seed-spn: that does not look like an SPN credential (expected sbsp1_...); nothing stored")
                return 1
            store.save_spn(spn)
            ok = store.load_spn() == spn
            del spn
            print(f"seed-spn: {'stored and read back' if ok else 'READ-BACK MISMATCH'} at "
                  f"{ob.mount}/{cfg.openbao_prefix}/{openbao.SPN_PATH}")
            return 0 if ok else 1
        if which == "migrate":
            return _openbao_migrate(cfg, store, args.delete_dpapi)
        if which == "rotate-spn":
            from .busclient import BusError as _BusError
            from .host import rotate_spn_now

            try:
                result = rotate_spn_now(cfg, store, lambda event, **kw: print(f"  {event} " + " ".join(
                    f"{k}={v}" for k, v in kw.items())))
            except _BusError as e:
                print(f"rotate-spn: the bus refused (HTTP {e.status}); the SPN is unchanged")
                return 1
            print({"rotated": "rotate-spn: rotated; the successor is stored in OpenBao and read back",
                   "replayed": "rotate-spn: the bus says this request was already done; nothing changed here",
                   "lost": "rotate-spn: FAILED to store the successor; the old SPN stops in 60 s. Rotate it from the "
                           "operator console, then wh openbao seed-spn"}[result])
            return 0 if result == "rotated" else 1
        # status
        end = openbao.leaf_not_after(leaf / openbao.LEAF_CRT)
        print(f"openbao: {'ENABLED' if ob.enabled else 'disabled'} in config.toml; {ob.url} mount {ob.mount} "
              f"prefix {cfg.openbao_prefix}")
        print(f"leaf: {', '.join(openbao.leaf_san(leaf / openbao.LEAF_CRT)) or 'none'}"
              + (f", {(end - time.time()) / 3600:.0f} h left" if end else "") + f" ({leaf})")
        client = store.client
        print(f"health: {'ok' if client.health() else 'UNREACHABLE'}")
        with client.session() as s:
            s.write("selftest", {"at": str(int(time.time()))})
            back = s.read("selftest")
            s.destroy("selftest")
        print(f"login and own-prefix write/read/destroy: {'ok' if back else 'READ FAILED'}")
        print(f"SPN: {'present' if store.has_spn() else 'missing (wh openbao seed-spn)'}; host identity "
              f"{cfg.host_agent}: {'present' if store.has(cfg.host_agent) else 'missing'}")
        return 0 if back else 1
    except openbao.OpenBaoError as e:
        print(f"{which}: failed ({e.what}, HTTP {e.status}); nothing secret was printed")
        return 1


def _openbao_migrate(cfg, store, delete_dpapi: bool) -> int:
    """Copy the SPN and every identity from the DPAPI store, read each back, and only then (with --delete-dpapi)
    remove the DPAPI folder. Worker identities matter: bus names are never reusable, so a worker whose credential
    is lost can never run under that name again."""
    dpapi = creds.Store(cfg.creds_dir)
    if not cfg.creds_dir.is_dir():
        print(f"migrate: no DPAPI store at {cfg.creds_dir}; nothing to do")
        return 0
    names = sorted(p.stem for p in cfg.creds_dir.glob("*.bin") if p.stem != "spn")
    copied, bad = 0, []
    if dpapi.has_spn():
        try:
            spn = dpapi.load_spn()
        except OSError:
            # Seen on a test host: over an SSH key sign-in DPAPI may have no keys to decrypt with.
            print("migrate: cannot decrypt the DPAPI store in this session (an SSH key sign-in may have no DPAPI "
                  "keys); run it signed in at the machine or over RDP, as this user. Nothing was changed.")
            return 1
        store.save_spn(spn)
        if store.load_spn() != spn:
            bad.append("spn")
        del spn
    for name in names:
        try:
            rec = dpapi.load(name)
        except (OSError, ValueError, LookupError):
            bad.append(name)
            continue
        if not creds.AGENT_RE.fullmatch(name) or (name != cfg.host_agent and
                                                  not name.startswith(cfg.agent_prefix + "-")):
            print(f"migrate: skipping {name} (not this host's prefix)")
            continue
        store.save(name, rec)
        if store.load(name).get("secret") != rec.get("secret"):
            bad.append(name)
        else:
            copied += 1
    print(f"migrate: SPN {'copied' if dpapi.has_spn() and 'spn' not in bad else 'not present' if not dpapi.has_spn() else 'FAILED'}; "
          f"{copied} of {len(names)} identities copied and read back")
    if bad:
        print(f"migrate: FAILED for {', '.join(bad)}; the DPAPI store is kept")
        return 1
    if delete_dpapi:
        import shutil

        shutil.rmtree(cfg.creds_dir)
        print(f"migrate: DPAPI store {cfg.creds_dir} deleted")
    else:
        print("migrate: DPAPI store kept; set [openbao] enabled = true, restart (wh stop / wh start), check a task, "
              "then run `wh openbao migrate --delete-dpapi`")
    return 0


def cmd_supervise(cfg, args) -> int:
    name = "StrugglebusWorkerHostSupervisor-" + hashlib.sha256(str(cfg.home).lower().encode()).hexdigest()[:12]
    mutex = None
    for prefix in ("Global\\", "Local\\"):
        try:
            mutex = winapi.single_instance(prefix + name)
            break
        except (OSError, NotImplementedError):
            continue
    if mutex is None and winapi.IS_WINDOWS:
        HostLog(cfg.logs_dir)("supervisor-already-running")
        return 3
    # EventLog: a crash restart or a rollback is also queued for the bus's event log (section 1b); the host sends it.
    log = EventLog(cfg.logs_dir, cfg.state_dir)
    try:
        return Supervisor(cfg, log=log).run()
    except BaseException as e:  # noqa: BLE001
        log.error("supervisor-fatal", e)
        raise


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="wh", description="strugglebus worker host")
    p.add_argument("--home", help="host home folder (default %%LOCALAPPDATA%%\\strugglebus-worker-host)")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("start", "stop", "drain", "pause", "resume"):
        sub.add_parser(name)
    s = sub.add_parser("status")
    s.add_argument("--post", action="store_true", help="also post a heartbeat")
    s = sub.add_parser("set-model")
    s.add_argument("model")
    s = sub.add_parser("cleanup")
    s.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("update-ghcp")
    s.add_argument("--when-idle", action="store_true")
    s = sub.add_parser("enrol")
    s.add_argument("--coordinator-id")
    s.add_argument("--import-identity", help="adopt an existing bus.py identity file (dry runs, migration)")
    s.add_argument("--spn-stdin", action="store_true", help="read the SPN credential from one line of stdin")
    s.add_argument("--code-stdin", action="store_true",
                   help="read the App's one-time host enrolment code from one line of stdin (the App's install script)")
    s = sub.add_parser("pin")
    s.add_argument("--coordinator-id", required=True)
    s = sub.add_parser("probe")
    s.add_argument("--out")
    fl = sub.add_parser("fleet", help="fleet.toml: what this host trusts, and entries for a PR")
    fsub = fl.add_subparsers(dest="fleet_cmd")
    s = fsub.add_parser("status")
    s.add_argument("--refresh", action="store_true", help="fetch and check fleet.toml now")
    s = fsub.add_parser("entry")
    s.add_argument("--host", action="store_true", help="this host's [[host]] entry")
    s.add_argument("--coordinator", help="the coordinator's bus agent_name")
    s.add_argument("--project")
    s.add_argument("--notes-repo")
    s.add_argument("--notes-channel")
    s.add_argument("--repos", nargs="+")
    s.add_argument("--engine", choices=fleet_mod.ENGINES, default="ghcp")
    s.add_argument("--agent-id")
    s = sub.add_parser("run", help="run the host in the foreground (what the supervisor runs)")
    s.add_argument("--max-seconds", type=float)
    s.add_argument("--echo", action="store_true")
    sub.add_parser("supervise", help="run the host and restart it after a crash (what the scheduled task runs)")
    sub.add_parser("panel", help="the desktop status window (started at sign-in by install.ps1)")
    sub.add_parser("selftest", help="check this code loads (self-update runs it on a staged release first)")
    up = sub.add_parser("update", help="self-update from signed releases: status, check, now")
    usub = up.add_subparsers(dest="update_cmd")
    usub.add_parser("status", help="what is installed, and the update in progress")
    usub.add_parser("check", help="fetch and check release.toml now (changes nothing)")
    usub.add_parser("now", help="apply a newer signed release as soon as no worker is running (announced first)")
    ob = sub.add_parser("openbao", help="host secrets in OpenBao: status, enrol, renew, seed-spn, migrate")
    osub = ob.add_subparsers(dest="openbao_cmd")
    osub.add_parser("status", help="leaf, health, a login with own-prefix write/read/destroy, what is stored")
    s = osub.add_parser("enrol", help="issue the leaf: the CSR from setup\\30-openbao.ps1 plus the one-time token")
    s.add_argument("--csr")
    s.add_argument("--token-stdin", action="store_true", help="read the token from one line of stdin")
    osub.add_parser("renew", help="renew the leaf now (the host does this hourly)")
    s = osub.add_parser("seed-spn", help="store the SPN credential in OpenBao (once per SPN)")
    s.add_argument("--spn-stdin", action="store_true", help="read the SPN credential from one line of stdin")
    osub.add_parser("rotate-spn", help="rotate this host's SPN now (also done in the nightly window, monthly)")
    s = osub.add_parser("migrate", help="copy the DPAPI store (SPN and every identity) into OpenBao")
    s.add_argument("--delete-dpapi", action="store_true", help="after a verified copy, delete the DPAPI store")
    args = p.parse_args(argv)
    if args.home:
        os.environ["WORKERHOST_HOME"] = args.home
    try:
        cfg = config_mod.load()
    except FileNotFoundError:
        print(f"no config at {config_mod.home_dir() / 'config.toml'}; run install.ps1 first")
        return 2
    except ValueError as e:
        print(f"config error: {e}")
        return 2
    handler = {"start": cmd_start, "stop": cmd_stop, "drain": cmd_drain, "pause": cmd_pause, "resume": cmd_resume,
               "status": cmd_status, "set-model": cmd_set_model, "cleanup": cmd_cleanup,
               "update-ghcp": cmd_update_ghcp, "enrol": cmd_enrol, "pin": cmd_pin, "probe": cmd_probe,
               "run": cmd_run, "supervise": cmd_supervise, "panel": lambda c, a: panel.run(c),
               "fleet": cmd_fleet_entry if getattr(args, "fleet_cmd", None) == "entry" else cmd_fleet_status,
               "selftest": cmd_selftest, "update": cmd_update, "openbao": cmd_openbao,
               }[args.cmd]
    if args.cmd == "fleet" and args.fleet_cmd is None:
        args.refresh = False
    return handler(cfg, args)


if __name__ == "__main__":
    raise SystemExit(main())
