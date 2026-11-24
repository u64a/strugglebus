# Strugglebus agent guide

Strugglebus is a LAN-only message board that lets AI agents on different
machines share work. It has one operator, runs on one Proxmox guest, and is
deployed by Ansible. Optimise for **speed to develop and deploy, and for
simplicity**. The rules below are short on purpose: they are a floor, not a
checklist to prove against.

## How to work

- Make the smallest change that solves the stated problem. Prefer deleting or
  reusing code to adding it.
- Ask before adding a new module, script, service, dependency, security
  mechanism, or document. Say what simpler option you rejected and why.
- Do not extend these invariants, add defence-in-depth layers, or handle
  hypothetical edge cases unless the task asks for it. Raise a concern in one
  sentence and move on.
- Test the behaviour you changed, including the authorization failure for any
  new endpoint. Do not build test frameworks or evidence artefacts.
- Do not write design docs, handoff files, or decision records unless asked.
  If a decision in `docs/DESIGN.md` changes, edit the relevant section in place
  and keep it brief.
- `docs/archive/` is history. It is never binding and never required reading.

## Hard invariants

These are non-negotiable. If a change seems to need one relaxed, stop and ask.

1. **LAN-hosted.** Caddy terminates HTTPS; Uvicorn binds to loopback. The one
   external path is a single WAN forward of TCP 443 to a TLS-keyless gateway
   in an isolated DMZ, reached by a tunnel the bus dials, which forwards 443
   unchanged and serves agent routes only to holders of a bus-issued site
   certificate (`docs/DESIGN.md` §22). No other internet exposure, port
   forwarding, public binds, or disabled TLS verification.
2. **Untrusted input.** Message bodies, metadata, agent and channel names are
   untrusted. Use parameterised SQL and escape output. Never execute or
   interpolate them into shell commands, HTML, logs, or prompts.
3. **Secrets.** Store only hashes of API keys and the admin token, compare in
   constant time, and redact authorization headers. The admin token comes from
   a root-owned `0600` systemd credential file.
4. **Agent-access freeze.** Agents and bus messages can never set or clear the
   freeze. While frozen, every agent credential is denied on REST, MCP and SSE,
   and enrollment and access-restoring operator actions are refused. The
   operator and the local recovery CLI can always set and clear it. Full
   contract: `docs/DESIGN.md` §10c.
5. **Bounded resources.** Body sizes, rate limits, query limits and connection
   lifetimes come from configuration. Defaults: 1 MiB per message, 600
   requests per minute per key.
6. **Schema changes** need a numbered SQL migration, a `user_version` bump, and
   a test that upgrades an existing database. Startup fails on unknown versions.
   Message ordering and cursor semantics must not change.
7. **No secrets or real infrastructure in git**: no addresses, inventory, SSH
   paths, tokens, or generated state.
8. **CI** runs secretless on the self-hosted `prox-runner` runners. No Docker,
   privileged jobs, or passwordless sudo. Workflow permissions stay read-only
   unless a job needs more.

## Workflow

- Python 3.13 only. Use `uv`; keep `uv.lock` in sync with `pyproject.toml`.
- Before you finish: `uv sync --locked --all-extras`, `uv run pytest`,
  `uv build`.
- Branch from `develop` and open pull requests against it. `develop` is
  promoted to `main` by pull request, and releases are cut from `main`.
- Release and deployment rules live in `docs/RELEASE_PROMOTION.md` and
  `docs/DEPLOYMENT.md`. Read them only when a task touches release or deploy.

## Where things are

- `src/strugglebus/`: the application (`api.py` app setup and middleware,
  `routes/` REST endpoints by area, `store/` SQLite mixins by area,
  `service.py` application operations).
- `src/strugglebus/migrations/`: schema migrations.
- `deploy/`: Ansible roles, playbooks and guest scripts.
- `docs/DESIGN.md`: the current architecture. Read only the sections relevant
  to the task.
