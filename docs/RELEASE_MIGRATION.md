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
| Bus | checksums and a manifest that come from the same release | none | **No** |

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

**What is needed** (to be designed and reviewed by u64-security before any code):

1. The release pipeline signs the release with a key held outside GitHub. The worker host already
   uses the owner's YubiKeys for this, so the same keys with a namespace of their own is the
   obvious choice.
2. Both update paths check that signature against keys that ship inside the installed bus, before
   anything from the new release is run, and refuse a release that fails.
3. A rule against going back to an older signed release.
4. One last release through the present path, which carries the check. From then on every update
   is checked. This is the same step the App took at 1.7.3.

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

- [ ] Design for the signature check, reviewed by u64-security.
- [ ] The check shipped and released through the present path.
- [ ] The release pipeline moved here from the private repository.
- [ ] A signed release that tells installed buses the new address. `NZCypher819/strugglebus-releases` kept read-only.

## Before or with the move

These are the owner's to do or approve.

- [ ] **The second organisation owner.** An owner can delete releases, move tags and turn off every rule on this page.
- [ ] **Release tags cannot be moved or deleted.** A tag ruleset here for `windows/v*` and `bus/v*`, and GitHub's immutable releases setting.

## Feature requests and bug reports

Issues are filed at `NZCypher819/strugglebus-releases` today. Where they should live after the
move is an open question for the owner.
