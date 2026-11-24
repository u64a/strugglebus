# Opt-in prepare-only updater bootstrap

This is a **local implementation, not host adoption approval**. No real App,
credential, systemd service or storage has been created or qualified by the
offline tests. Debian 13 adoption needs a separate owner decision and live
distinct-UID, socket, confinement, filesystem and resource-limit qualification.
The ordinary configure, deploy, publisher and release controller paths do not
invoke `deploy/playbooks/updater_bootstrap.yml`.

## Future operator prerequisites

- Independently acquire the exact authenticated immutable canonical release and
  record its approved package version, commit, tree and manifest SHA-256.
  Qualify its **installed updater code**, not just its release envelope. Supply
  these pins through private inventory and give the version-bound approval
  `bootstrap-updater-VERSION` and `strugglebus_assert_qualified_updater_bootstrap`.
  Neither a worker-prepared candidate nor a mutable checkout is trusted code.
- Existing standard bus data `/var/lib/strugglebus` must belong to its non-root
  account/group with mode `0700` or `0750`. Reserve UID **975** and GID **975**
  solely for `strugglebus-updater`, with no supplementary groups or login shell.
  Conflicting existing accounts/groups are refused, not reassigned.
  This first profile also requires the standard `/run/strugglebus`,
  `/etc/strugglebus`, `/var/lib/strugglebus/strugglebus.db` and
  `/var/backups/strugglebus` runtime/configuration/database/backup paths.
  Mode and group separation alone do not exclude named-user ACLs. Both
  `system.posix_acl_access` and `system.posix_acl_default` must be absent on
  the bus-data root. Bootstrap queries them without following symlinks and
  accepts only explicit `ENODATA` absence; any present ACL, unavailable API,
  permission error or unsupported-filesystem result fails closed. It never
  removes ACLs or accepts an inventory assertion in place of this check.
- Separately provision an already mounted **persistent ext4 block filesystem**
  at `/var/lib/strugglebus-updater-cache`. This first profile requires a unique
  UUID-backed `/etc/fstab` entry, `rw,nodev,nosuid,noexec`, root-owned protected
  ancestry, and an exact mount-root contract of
  `root:strugglebus-updater 0710`. The worker group may traverse that root to
  its private `state` child but cannot list or write the mount root. The profile
  refuses aliases, nested mounts or unrelated data, requires a different device
  from bus data and requires the underlying block device and filesystem each no
  larger than **1 GiB**. It verifies actual mountinfo, device identity, block
  size and statvfs capacity; there is no `quota_verified` assertion.
  Bootstrap never creates, resizes or mounts disks.
  The fstab dump/pass fields are `0 2`; optional mount flags are limited to
  `relatime`, `noatime`, `discard` and `errors=remount-ro`. Conflicting flags,
  ambiguous `defaults`, user-mount permissions and unknown options are refused.
- **LXC profile.** When the root-owned, non-writable `/run/systemd/container`
  marker reads `lxc`, the cache may instead be a host-attached Proxmox mount
  point (for example `mp0: …,mp=/var/lib/strugglebus-updater-cache,`
  `mountoptions=nodev;nosuid;noexec,size=1G`). The guest has no block node or
  fstab entry for it, so those two checks are skipped; persistence comes from
  the container configuration. Mountinfo flags, ext4, the dedicated mount root,
  device separation, the 1 GiB sysfs size ceiling and statvfs capacity are still
  enforced. Replace the mount's `lost+found` with a root-owned one
  (`mklost+found`) if it shows an unmapped owner.
- Default budgets require **512 MiB** for the prepared/quarantine pair,
  **4 MiB** for journal/receipts and **256 MiB** free-space reserve. An empty
  cache must have all those bytes available after filesystem overhead; reruns
  retain the reserve and must still have total capacity for the complete
  budget. Limits cannot increase ceilings; the 256 MiB reserve and 60-second
  check cooldown are safety **floors**, so only increases may tighten them.
  Their integer values remain bounded by the worker's reviewed `1073741824`
  maximum, and an increased reserve must still fit the complete budget inside
  the actual cache filesystem and its free-space checks. Candidate storage must fit
  twice inside the artifact budget. There is one prepared and one quarantine
  slot, never an unbounded queue.
- Through protected local operator setup, provide the worker's bounded JSON
  configuration at `/etc/strugglebus-updater/worker.json`, initially root-owned
  `0600`. Its exact keys are `version` (1), `application_uid`,
  `application_data_dir`, `cache_dir`, `app_id`, `installation_id`,
  `repository_id`, `limits`. The data path is `/var/lib/strugglebus`; cache path
  is `/var/lib/strugglebus-updater-cache/state`. `limits: {}` selects reviewed
  defaults. Actual numeric App/installation/repository IDs belong only in this
  protected local file, never tracked inventory. Bootstrap makes it
  root:`strugglebus-updater` `0640`; it never generates or replaces its contents.
  Its root-owned parent must permit worker traversal (`0755`); the separate
  credential directory may remain root-only.
- A separately approved, single-repository Contents-read/Metadata-read GitHub
  App supplies a real root-owned `0600` private key beneath
  `/etc/strugglebus-updater/credentials/`. Supply its guest path as
  `strugglebus_updater_credential_source`, not key material or an environment
  variable. Preflight examines metadata without reading the key.
  `LoadCredential=github-app-key:...` projects it only to the worker through
  `CREDENTIALS_DIRECTORY/github-app-key`. No publication credential is reused.
  The installed credential reader accepts a worker-owned `0400` projection
  beneath a worker-owned `0500` immediate directory with protected root-owned
  ancestors; its key payload limit is 16 KiB. This is distinct from the root
  `0600` source. Its metadata checks are not a read-only-mount attestation:
  Debian qualification must prove the systemd projection is actually read-only,
  including refusal of worker chmod/replacement attempts. File mode alone is
  insufficient when that worker owns the inode. `init` and `status` never open
  either credential; only an authorized job constructs the projected source.

## What the separate bootstrap changes

The bootstrap playbook, role and pinned preflight helper are a separately
reviewed **controller payload**, not additions to the canonical release support
archive. That archive's file list and published-byte policy remain unchanged;
the archive alone cannot supply this bootstrap. Future adoption must deliver
these controller files through an independently approved immutable controller
bundle/revision. Distributing them inside canonical release support instead
would require a separate, explicit support-policy decision. No downloaded or
worker-prepared candidate helper supplies controller/bootstrap authority.

Controller qualification must record the **exact approved source commit and
tree**, an independently verified controller-bundle SHA-256 and the reviewed
controller dependency environment. Its inventory must cover this playbook,
`deploy/roles/updater/`, the pinned preflight helper, the shared validated-helper
task and release-envelope resolver, and their trusted script/module dependencies.
The approved payload must remain non-writable by application/worker identities.
The current uncommitted implementation is not itself a qualified distribution;
choosing, packaging, independently verifying and delivering that exact
controller payload is an explicit later adoption gate. The helper's embedded
checksum is a per-file integrity check, not a substitute for that approval.

The read-only preflight is checksum pinned. The existing release-envelope
resolver validates approved controller artifacts offline without invoking any
deployment action. Bootstrap installs the approved wheel and hash-locked binary
dependencies into `/opt/strugglebus-updater/releases/VERSION/venv`, root-owned
and non-writable by either service. It reuses the existing pinned uv provenance,
disallows source builds and never imports checkout/candidate helpers. A partial
or differently pinned existing installation fails closed for separate recovery.
Existing updater units must match exactly; this first bootstrap is not a worker
upgrade/restart path. A rerun leaves an active matching worker alone instead of
contending with its history lock. For a dormant worker, bootstrap examines only
the exact journal's metadata: an existing bounded worker-owned `0600` regular
single-link journal is validated with credential-free `status`; only an absent
journal selects `init`. The worker independently rejects non-pristine storage.
Before that selection, host preflight requires an empty state directory or only
the exact empty worker-owned `0600` single-link `updater-worker.lock` when the
journal is absent. Orphaned preparations or other entries halt bootstrap.
An empty existing state directory still requires the full initial free-space
budget, not just the initialized-history reserve.
Repeated `init` is deliberately **not** idempotent: it refuses existing history.
A failed `status`, corrupt/unknown journal or unsafe metadata halts bootstrap;
there is no fallback to initialization, deletion, repair or history reset.
Previously published root-owned updater units also forbid initializing a now
missing journal: units are published only after successful history validation,
so their presence is evidence of an earlier bootstrap, not pristine storage.

It creates only the worker identity, its private cache child, updater code and
updater units. The installed public CLI remains:

```text
python -I -m strugglebus.update_worker init --config ABSOLUTE_CONFIG
python -I -m strugglebus.update_worker status --config ABSOLUTE_CONFIG
python -I -m strugglebus.update_worker serve --config ABSOLUTE_CONFIG
```

`init`/`status` use no credential or network. `serve` requires the inherited
systemd listener; no public test/source/listener bypass is provided. Socket
activation uses root-owned `0660` `/run/strugglebus-updater/worker.sock`,
the bus's existing group and a root-managed non-writable parent. The worker
never joins that group. The bus has no worker dependency and stays healthy when
the worker or its credential is unavailable.

The worker has no inbound TCP bind, privileges or writable system code.
Trusted fixed-source transport enforces HTTPS/repository/host policy: systemd
does **not** claim a DNS-aware GitHub-only firewall. This profile requires bus
data traversal to be denied by private owner/group permissions and worker group
isolation and absence of extended access/default ACLs on the data root; actual
UID, supplementary-group, ACL and mount behavior must still be qualified on
Debian. Its directory is read-only, and database/backups/configuration/runtime/
release paths are explicitly inaccessible. Only cache state is writable.
Resource controls are 512 MiB memory, no swap, 16 tasks, CPU quota 25%, CPU and
I/O weights 10, 64 file descriptors and no core dumps. The syscall policy permits
the worker to terminate its own bounded job process.

The bus-data **directory metadata remains visible intentionally**: worker startup
checks the actual directory owner and `st_dev`. A read-only bind must preserve
that identity; the separate root preflight measures real devices, persistent
mount topology and capacity outside the worker namespace. Do not replace the
whole data root with `InaccessiblePaths` and then treat its placeholder device
as evidence of filesystem separation. Full root masking would require an
explicitly approved immutable topology-attestation/runtime contract; the fixed
configuration currently carries `application_data_dir`, not a preattested
device identity. No bypass flag or claimed synthetic host proof resolves that
different profile. Real namespace and content-denial qualification remains
mandatory before adopting the current metadata-visible profile.

No bus restart, configuration change, database read/migration, backup action,
freeze transition or current-release selection occurs. No prepared package is
installed or activated. Check mode is not a substitute for real host inspection.

## Application adoption is separate

Bootstrap does **not** set `strugglebus_updater_socket_path`. Until a separately
approved application configuration adopts the socket, updates remain disabled.
An updater-capable wheel may explicitly set that variable and optionally narrow:

| Setting | Default / maximum |
| --- | --- |
| `strugglebus_updater_confirm_session_per_minute` | 3 |
| `strugglebus_updater_confirm_global_per_minute` | 6 |
| `strugglebus_updater_review_seconds` | 300 |
| `strugglebus_updater_review_tickets` | 8 |

The corresponding environment names are `STRUGGLEBUS_` plus the uppercase
setting name without the `strugglebus_` prefix. Ordinary templates omit all
five unless explicitly supplied, preserving compatibility with older releases.
They are `STRUGGLEBUS_UPDATER_SOCKET_PATH`,
`STRUGGLEBUS_UPDATER_CONFIRM_SESSION_PER_MINUTE`,
`STRUGGLEBUS_UPDATER_CONFIRM_GLOBAL_PER_MINUTE`,
`STRUGGLEBUS_UPDATER_REVIEW_SECONDS` and `STRUGGLEBUS_UPDATER_REVIEW_TICKETS`.
Maintenance validates candidate support, bounded values and socket separation
before activation and binds rendered settings into its existing provenance.
Adopting or changing these settings is not part of this bootstrap.
Ordinary setting admission is carried by the already-listed canonical
`deploy/roles/systemd/tasks/operator_credential.yml`; maintenance retains the
same checks inline. No new ordinary task include or canonical support member
is required. This does not make the support archive a complete controller tree.

## Offline evidence versus adoption gates

`deploy/tests/updater_bootstrap_unit.py` checks static wiring, checksums, isolation
and hardening contracts. `tests/test_updater_bootstrap.py` injects synthetic
accounts, mounts, capacity, file metadata and protected configuration. These
tests do not demonstrate real systemd behavior, Unix UID boundaries, GitHub
permissions, persistent disk behavior, DNS/HTTPS egress or 512 MiB/16-task
viability on Debian. Those remain explicit future adoption gates.
