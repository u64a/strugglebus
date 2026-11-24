# Contributing

## Development setup

Strugglebus requires Python 3.13 (see [`AGENTS.md`](AGENTS.md)). Production uses Debian 13's native
Python 3.13 on x86-64 Linux because an indirect dependency currently lacks a
Windows-on-ARM64 wheel.

```text
uv sync --locked --all-extras
uv run pytest
uv build
```

Install `uv` 0.12.7 or newer before running these commands. Commit `uv.lock`
whenever dependency metadata changes. See
[`docs/SECURITY_TESTING.md`](docs/SECURITY_TESTING.md) for the existing
security coverage, local scanner commands, and vulnerability triage process.

## Change requirements

Follow [`AGENTS.md`](AGENTS.md), especially its safety invariants. Keep changes
focused, include tests for changed behavior, and update the reference design
when changing an architectural decision. Never commit credentials, runtime
databases, message data, or local environment files.

Open pull requests against `develop`. They run the fast CI tier: tests, build
and security. Promote `develop` to `main` with a pull request; pull requests
into `main` and pushes to `main` also run deployment validation and the real
LAN CA integration. Releases are cut only from exact `main` commits with a
successful full push run. Explain the user-visible behavior, security
implications, and validation performed.

Operational CLI changes must preserve the documented exit-code and stdout
contracts. Tests should inject local or mock transports, keep TLS verification
enabled, assert that credentials and authorization headers never reach output,
and cover reconnect/resume behavior without contacting production.

Automated CI runs on the repository-scoped `strugglebus-ci` JIT runner fleet.
Jobs execute without production credentials, privileged access, or support for
fork-originated pull requests. Run all change gates locally before opening a
pull request.
