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
| Bus | private `NZCypher819/strugglebus` | `NZCypher819/strugglebus-releases` releases | the updaters have that repository built in | Planned, see step 3 |

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
- [x] Release tags protected here (see "Before or with the move").
- [ ] A signed App release, published at the old place, that reads updates from here.
- [ ] `release-signed.ps1` publishes here. `NZCypher819/StruggleApp-Privacy` kept read-only.

Copies older than that release keep reading the old place, so it must stay up.

### 3. Bus (bus-dev)

Agreed in #humans on 27 November 2026 (bus messages 28851 to 28853) with u64-security and
prox-manager.

**Why it can be simpler than the present pipeline.** That pipeline made GitHub itself the proof
of who published: a private repository, a qualification on our own runner, a GitHub App that
publishes an immutable private release, then a hand-run mirror to a public one. Since 0.2.72 the
proof is the owner's signature over the five files. So the new pipeline is shaped like the
Windows App's.

**The pipeline, all in this repository**

1. The owner starts the "Bus release build" workflow for a commit on `main`. It runs on GitHub's
   own runners, in a container image pinned by digest, and runs `bus/scripts/build_release.sh`:
   the wheel is built once and normalised, the five release files are made and validated, and
   they are kept as an artifact. It publishes nothing and holds no secrets.
2. On the owner's PC, `bus/scripts/release_here.py compare` builds the same five files again from
   a fresh clone of that commit, with the same script in the same image. uv is fetched and
   checked against the hash in the source, the exact Python version is named so uv checks its
   hash too, and dependencies are installed by hash from the lock. Neither build shares files or
   caches with the other.
3. The script refuses to go on unless all five files from the two builds are byte for byte the
   same, and says which differ. A compromised runner alone can then not get a bad release signed.
4. It prints the commits since the previous `bus/v*` tag that touch `bus/`, one line each, for the
   owner to read, and writes the statement. The owner signs it with a hardware key.
5. `release_here.py publish` refuses unless the signature is by a release key for those files.
   It then makes the annotated tag `bus/vX.Y.Z` carrying the statement and signature, publishes
   the release, and checks that GitHub holds exactly the signed files, immutably.

**The tag comes last, not first.** The first plan had the tag start the build. But the tag's
message carries the signature, the signature covers the hashes of the built files, and a
`bus/v*` tag can never be moved once made. So the build is started for a commit, and the tag is
made at publishing, already signed.

**No self-hosted runner on this repository.** `prox-runner` builds and qualifies today. On a
public repository it would run code from anyone's pull request on the owner's network. The two
checks that only ran there, "Deployment validation" and "Isolated LAN CA integration", use only
localhost (prox-manager read the code); they move to GitHub's runners, and the private runner's
copies are retired only after a green run here.

**Teaching installed buses the new address**

- **0.2.73 is the move and nothing else.** It is the last release published at the old place. It
  changes where the updaters look to this repository and to tags named `bus/v*`.
- Both updaters find bus releases **by tag**, not by reading the repository's list of releases.
  The list is shared with the App, which releases more often, so a bus release would in time be
  pushed off the end of any page of it and a bus would quietly stop seeing updates (found in
  review by u64-security, bus message 28876). The question "which tags start `bus/v`" is answered
  with those alone, whatever else is published.
- A tag is not a release. Anyone who can push can make a tag, so an updater takes the newest tag
  that has a published release, trying the newest five. A stray tag cannot hide a real update,
  and a release still installs only if a release key signed it.
- Tags are never deleted, so their number only grows. An updater reads up to a thousand. If there
  are ever more and no update is found among those read, the check fails where it can be seen;
  it never reports "nothing newer".
- The self-hosted fetcher then asks the old place as well and takes the newer of the two, so a
  bus is not left without updates if it cannot use the new place. That is two anonymous calls per
  check where there was one, and a third when there is an update to fetch.
- Ansible installs name the release repository in `/etc/strugglebus-updater/worker.json`, which
  the operator supplies. The 0.2.73 updater accepts a file naming either this repository
  (`u64a/strugglebus` for both values) or the old pair, so the file does not have to change at
  the moment of the install, and a rollback to 0.2.72 needs the old pair still in place. The file
  is changed afterwards, once 0.2.74 is installed and a rollback to 0.2.72 is no longer wanted.
  Whatever the file says, a 0.2.73 Ansible install reads only this repository.
- A 0.2.73 Ansible install accepts only a release built here (its manifest names this
  repository). So after 0.2.73 there is no further release from the old pipeline for those
  installs: the way back is the rollback to 0.2.72.
- All of this is tested on a non-production Ansible install first, including a release list
  that also holds a newer App release.
- **0.2.74 is the first release from here**, and carries schema 25 (the host dashboard, host
  events and the stored event log).
- `NZCypher819/strugglebus-releases` stays, read-only, with 0.2.73 as its last release. A bus
  older than 0.2.73 that updates later gets 0.2.73 from there and then moves on.
- The signed statement does not change. A signature is good wherever the files are served from.

**The source matters more than the build.** Both builds faithfully build whatever is on `main`.
So the files that decide what a bus trusts get the owner's review, like the worker host:
`release_signature.py`, `selfhost/fetch_release.py`, `update_source.py`, `update_storage.py`,
`release_validation.py`, `maintenance_runtime.py`, the updater and maintenance units, and the
publish scripts. This needs the owner's yes to add them to `.github/CODEOWNERS`.

- [x] Design for the signature check, reviewed by u64-security (bus messages 28770 to 28772).
- [x] The check shipped and released through the present path: 0.2.72, 27 November 2026.
- [x] The owner's yes to CODEOWNERS for the bus's trust files (pull request 35).
- [x] Tag rules: `windows/v*` and `bus/v*` tags cannot be moved or deleted, by anyone.
- [ ] "Deployment validation" and "Isolated LAN CA integration" green on GitHub's runners.
- [x] The build workflow and the second build. GitHub's runner and the owner's PC built the
      same commit to five byte-identical files (pull request 38).
- [x] The sign-and-publish script (`bus/scripts/release_here.py`), rehearsed against real GitHub
      in a scratch repository with the same tag rules and immutable releases, 27 November 2026.
      The first rehearsal found that an upload with a guessed content type is refused by an
      installed updater; the script now states each type and checks the draft with the updater's
      own check before publishing. The second rehearsal's release was found, downloaded and
      verified by the 0.2.73 updater's code (pull requests 39, 41 and 43).
- [x] 0.2.73's source fixed: commit `74e2ea6` on `main` (pull request 50) is the move and nothing
      else. Schema 25 merges after it.
- [x] The updaters read this repository and find releases by `bus/v*` tag (pull request 37).
- [ ] That tested on a non-production install: update, rollback, and the feed unavailable.
- [ ] 0.2.73 published at the old place and installed on the production bus.
- [ ] 0.2.74 published here. `NZCypher819/strugglebus-releases` kept read-only.
- [ ] `worker.json` on the production bus changed to name this repository.

## Before or with the move

These are the owner's to do or approve.

- [ ] **The second organisation owner.** An owner can delete releases, move tags and turn off every rule on this page.
- [x] **Release tags cannot be moved or deleted.** A tag ruleset here for `windows/v*` and `bus/v*`, and GitHub's immutable releases setting.

## Feature requests and bug reports

Issues are filed at `NZCypher819/strugglebus-releases` today. Where they should live after the
move is an open question for the owner.
