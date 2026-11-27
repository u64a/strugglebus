# Moving releases into this repository

The source for the bus, the Windows App and the worker host lives here, in `u64a/strugglebus`.
Their releases do not yet. This page is the plan for bringing them under the same roof, and the
record of how far it has got. Update it in the same pull request as each step.

Agreed in #humans on 27 November 2026 (bus messages 28758 to 28762) by the owner, bus-dev,
sbworkerhost-project and u64-security.

## Where things are

| Product | Built from | Published to | What holds it there | Status |
|---|---|---|---|---|
| Worker host | private `NZCypher819/strugglebus-worker-host` | the same private repository, as a signed file | hosts read `release.toml` there | **Moving now** |
| Windows App | this repository, tag `windows/vX.Y.Z` | `NZCypher819/StruggleApp-Privacy` releases | every installed App checks that repository | Not started |
| Bus | private `NZCypher819/strugglebus` | `NZCypher819/strugglebus-releases` releases | the updaters have that repository built in | Blocked, see below |

## The rule that makes one repository safe

**Publishing a release must never be enough to run code.**

Anyone with write access to this repository can publish here: every agent working on the owner's
token, and every owner of the organisation. So each product's updater must check a signature made
with a key that is not in GitHub, and refuse anything else.

| Product | What its updater checks | Key held | Meets the rule |
|---|---|---|---|
| Worker host | an SSH signature over `release.toml`, against keys pinned on each host; a serial that only goes up | the owner's YubiKeys | Yes |
| Windows App, from 1.7.3 | every file against a list signed for that version; the signer's thumbprint; a newer version (`app/windows/StruggleBusMonitor/UpdateTrust.cs`) | the code-signing certificate, in the certificate authority's cloud, usable only on the owner's PC | Yes |
| Bus, up to 0.2.71 | checksums and a manifest that come from the same release | none | **No** |
| Bus, from 0.2.72 | every file against a statement signed for that version; a newer version (`bus/docs/RELEASE_SIGNING.md`) | the owner's YubiKeys | Yes, once 0.2.72 is installed |

## The bus does not meet the rule yet

Checked in the source on 27 November 2026. Neither of the bus's two update paths checks a
signature. Both trust GitHub: its TLS, and who is allowed to publish to the releases repository.

- **Self-hosted installs** (Debian or Proxmox container, Docker): `bus/src/strugglebus/selfhost/fetch_release.py`
  takes the newest release, checks the wheel and lock file against `SHA256SUMS` from that same
  release, and then `strugglebus-update` runs the new release's own `install.sh` as root. Daily, unattended.
- **Ansible-deployed servers**: `update_source.py` and `release_validation.py` check much more
  (an annotated tag, a release GitHub marks immutable, a canonical manifest, hashes of every file),
  but every one of those comes from the same releases repository. The code says so itself:
  "Offline verification establishes integrity and policy, not publisher identity."

So today, write access to `NZCypher819/strugglebus-releases` is enough to run code as root on a
bus. That is true before any move, and it is the thing to fix first. The bus does not move until
it is fixed.

**What is needed.** u64-security's requirements (bus message 28765), which the design must meet:

1. **A signature with a key outside GitHub.** The owner's YubiKeys, as the worker host uses, but in
   a namespace of its own (`strugglebus-bus-release`), so a signed worker host release can never
   be replayed as a bus release or the other way round.
2. **Keys pinned by fingerprint in the installed bus**, in a root-owned file the bus's service
   user cannot write. Current and next keys; changed only by a signed release.
3. **Checked before any code from the new release runs, by the updater already installed.** The
   signed manifest covers everything that runs or is run: the wheel, the lock file, `install.sh`
   and every helper script. Nothing from the new release is run, sourced or imported first.
4. **No going back.** The highest installed signed serial is kept root-owned, and anything not
   above it is refused.
5. **One last release through the present path** carries the check, as the App's 1.7.3 did. It is
   trusted through today's weak path, once. u64-security verifies its files against the tag
   before U64's bus takes it, and testers are told to take it promptly.

**Until then** (proposed by u64-security; the first is the owner's decision):

- [ ] U64's bus applies a release only on the owner's say: automatic updates paused in the web
      console (Updates, "Pause automatic updates"). Manual updates still work.
- [ ] u64-security alerts on every new release in the releases repository, and on every update
      the bus applies.

## Order

One product at a time, least risky first. Each move is the same three steps:

1. a last release at the old place that tells installed copies the new address;
2. releases at the new place from then on;
3. the old repository kept, read-only, until nothing points at it.

### 1. Worker host (in progress, sbworkerhost-project)

Its release is a signed file in the tree, not a GitHub Release, so it needs no tags here.

- [ ] Public pull request adding `worker-host/release.toml` and `.sig` (serial 8). Owner signs and merges.
- [ ] Private pull request, the last release there (serial 7) with `moved_to = u64a/strugglebus:worker-host`. Owner signs and merges.
- [ ] Both hosts go 6 to 7 from the private repository, then 7 to 8 from this one, which proves the new address.
- [ ] The Surface's `[remotes]` narrowed from all of GitHub to the owners its coordinators use (u64-security).

Afterwards the private repository stays only for `fleet.toml`, until hosts read the fleet from the bus.

### 2. Windows App (bus-dev)

- [ ] Prove the App's updater finds the right release when other releases sit beside it in one repository, reading only `windows/` tags.
- [ ] Release tags protected here (see "Before or with the move").
- [ ] A signed App release, published at the old place, that reads updates from here.
- [ ] `release-signed.ps1` publishes here. `NZCypher819/StruggleApp-Privacy` kept read-only.

Copies older than that release keep reading the old place, so it must stay up.

### 3. Bus (bus-dev, after the signature check)

- [x] Design for the signature check, reviewed by u64-security (bus messages 28770 to 28772).
- [ ] The check shipped and released through the present path (0.2.72).
- [ ] The release pipeline moved here from the private repository.
- [ ] A signed release that tells installed buses the new address. `NZCypher819/strugglebus-releases` kept read-only.

## Before or with the move

These are the owner's to do or approve.

- [ ] **The second organisation owner.** An owner can delete releases, move tags and turn off every rule on this page.
- [ ] **Release tags cannot be moved or deleted.** A tag ruleset here for `windows/v*` and `bus/v*`, and GitHub's immutable releases setting.

## Feature requests and bug reports

Issues are filed at `NZCypher819/strugglebus-releases` today. Where they should live after the
move is an open question for the owner.
