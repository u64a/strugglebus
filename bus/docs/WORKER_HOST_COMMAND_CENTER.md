# The Windows App as the worker hosts' command center: bus and App side

Status: **reviewed by u64-security on 24 Nov 2026 (bus message 28470). Partly built: see "What is
built" at the end. Nothing is released.**

The review found the design sound and accepted remote control for the first release once its
conditions are written into both documents. They are, here and in the worker host document; the
section "Security review" lists each one and where it is met.

This is the bus and Windows App half of a plan agreed with `sbworkerhost-project` on the bus
(#strugglebus-improvements, messages 28458 to 28466, 24 Nov 2026). The worker host half, which holds
the status, script, fleet and command contracts, is `docs/app-host-integration.md` in the
strugglebus-worker-host repository. Where the two disagree, that is a mistake to fix, not a choice.

## Goal

A new user installs StruggleBus, opens the Windows App, and from the App:

- puts a worker host on each Windows 11 PC on their LAN;
- sees the state of every host;
- adds and signs coordinators;
- pauses, resumes, drains or updates a host.

They do not edit a file, run git or handle a secret.

## Decisions already made by the owner

- Remote control (pause, resume, drain, update) is in the first release, subject to the security review.
- The host runs under a dedicated Windows account by default. The person deploying can opt out.

## Rules that do not change

- The bus stays LAN only.
- A bus message is data, never a command. Authority comes only from a signature by a key that an
  administrator pinned on the host.
- The bus never verifies or interprets a fleet document or a host command. It stores and carries.
  A compromised bus can withhold; it cannot forge.
- Agents cannot set or clear the global freeze.
- Every new operator action needs an enrolled operator device plus the Windows Hello write grant,
  and an audit reason.
- Schema changes ship with a migration.

## Stages

All four are in the first release. They are built and released in this order.

| Stage | What the user gets | Bus | App |
|---|---|---|---|
| A | Hosts page | nothing new | reads status and last-seen |
| B | Add a host | host enrolment code | Add-host screen, the script |
| C | Coordinators and signing | site document store | site key; add, sign, publish |
| D | Pause, resume, drain, update | operator command post | sign and send a command |

## Bus changes

### B. Host enrolment code

**Mint:** `POST /api/mobile/enrollments/hosts`, beside the existing agent, service principal and
device enrolment calls, with the same guard.

- Input: the host prefix, `host-<hostname>`. Pattern `^[a-z0-9]+(?:-[a-z0-9]+)*$`, 2 to 31 characters.
- Output: a single-use code of the form `sbhe1_...`, shown once, valid for 15 minutes at most.
- The code carries at least 128 bits of randomness. The bus stores only a hash of it and compares
  in constant time.
- Refused if a service principal of that name exists and is not retired.

**Redeem:** `POST /api/hosts/enrollments/redeem`. The code is the bearer token, as every other
enrolment code on the bus is, and it is the only credential on the call. TLS is checked against the
pinned LAN root. The body is the host's request id.

- The bus creates a service principal whose name and agent name prefix are both exactly the prefix,
  and returns its credential once.
- The same request id may be presented again until the code expires, so a dropped connection does
  not burn the code. The bus keeps only a hash of a credential, so a repeat issues a new one and
  revokes the earlier one. Any other reuse is refused, and so is a repeat once the principal has
  been blocked.
- A caller without the right code learns nothing: an unknown code and a wrong secret are the same
  refusal, and "expired" and "name taken" are only said to a caller who presented the right one.
- The call is rate limited, because it takes no credential.
- The bus keeps the redeem request id and the redeeming address with the service principal, and
  returns both to the App. The App needs them for the confirmation code below.

After that the host is an ordinary service principal. It mints its workers and rotates its own
credential with the calls that exist today. Block and Retire in the App already apply to it, and so
does the global freeze. There is one service principal per host.

### C. Site document store

- One document per name. The first release has one name, `fleet`.
- **Write:** operator device plus Windows Hello. Body: the document bytes, the detached signature,
  and the serial as a number.
- **Read:** any enrolled host or agent. Returns the bytes, the signature, the serial and when it was
  stored.
- The bus returns exactly the bytes it was given. It refuses a write whose serial is not higher than
  the stored one. That guards against operator mistakes only; the host's own check is the real one.
- 64 KB cap on the document.
- New table, so a migration.

### D. Operator command post

An operator device can post only in #humans today, and cannot attach metadata. Rather than open
operator posting generally, add one narrow call.

- `POST /api/mobile/hosts/commands`, with the same guard as other operator actions.
- Input: the channel, the command document (base64, 1 KB at most) and its signature (4 KB at most).
- The bus posts a message on that channel as `human:operator`, kind `question`, with a fixed body
  and the two values in metadata under `sb_host_command`.
- The database rule that keeps the operator author in #humans admits exactly this shape and nothing
  else.
- The bus checks sizes and nothing else. The fixed body is set by the bus, not sent by the App.

### Audit

The bus audit log gets a line for each of these, in a fixed format the site's monitoring can match:

- host enrolment: mint, redeem and every failed redeem, with the source address;
- site document writes: name, serial and the signer's key fingerprint;
- command posts: verb, host, nonce and the operator device.

For the last two the bus reads the serial, fingerprint, verb, host and nonce from what the App sends
alongside the signed bytes. They are for the log only; the host still trusts nothing but the
signature.

## App changes

### A. Hosts page

- One row per host, built from the newest `sb_host_status` metadata on the hosts' channel: state,
  busy and max workers, version, engines and whether each is signed in, account, held clones,
  outbox, fleet serial, last problem.
- **Alive or not** comes from the bus's own last-seen time for `<prefix>-host`, not from the status
  message. An idle host calls the bus every 10 seconds, so a host is shown as not responding after
  90 seconds of silence.
- Every status field is untrusted display text, shown as plain text and never as markup. Nothing
  in it is acted on.
- Standing warnings the host reports stay on the row for as long as they are present. A host that
  is **not** running under a dedicated account shows a permanent warning that its workers have the
  whole of that person's account, not just a flag.
- Read only.

### B. Add a host

1. The operator types the PC's name and picks the engines and whether to use a dedicated account.
2. Windows Hello, then the App mints the enrolment code.
3. The App hands over two files and edits neither one's logic (decided after the review, bus
   messages 28497 and 28498):
   - `bootstrap.ps1`, the worker host's installer, shipped in the App unchanged. Once releases are
     Authenticode-signed the App shows the expected publisher. Until then it shows the file's full
     SHA-256 and the `Get-FileHash` command to run on the target PC before running the script.
   - `sbhost-enrol.json`, the values for this one host. It is data and is never executed, so
     changing it cannot run code. It has one canonical form: one line of JSON in a fixed key order
     with no spaces, ASCII only, then one line feed. The installer re-renders the file from the
     values it read and refuses any difference, and re-checks every value against a fixed pattern.
4. When it saves the data file, the App shows a short digest of it (the first 16 hex characters of
   its SHA-256, in fours) and the fingerprint of every signer in it. The installer prints the same
   before it does anything, and the operator compares them. This holds because the code printing
   them is the fixed installer, not the file being checked.
5. The App tells the operator the data file holds a one-time code. The installer blanks the code in
   the file once it has been redeemed.
6. The row shows "waiting for install", then "needs sign-in" or "needs fleet", with the address the
   code was redeemed from.
7. **Confirming it is the right host.** The bootstrap prints a confirmation code: the first 8 hex
   characters of SHA-256 over the host's agent id and the redeem request id, joined by a newline.
   The App works out the same value from what the bus recorded and shows it. The operator compares
   the two. If they differ, someone else redeemed the code: the App retires that service principal
   and signs nothing.
8. Only then does the App add the host to the fleet document, raise the serial, sign and publish
   (Windows Hello again). The host takes no work until the fleet lists it.

### C. Coordinators and signing

- At first use the App creates the site key: a Windows Hello key, RSA-2048, so every signature
  needs Hello. Signatures are in OpenSSH's SSHSIG format (sha512, `rsa-sha2-512`), namespace
  `strugglebus-fleet`.
- **The App signs only when it is running as a registered package, with a key it made while
  packaged.** Windows scopes a Hello key to one program only for packaged programs, and a key made
  while unpackaged stays unscoped afterwards. Without both, the App is publish-only: it shows the
  change and publishes a document signed elsewhere, and it tells the operator to make a new key and
  re-pin it on the hosts. See "Open risks" and "Decisions since the review".
- **A second signer is required before the first publish.** The operator pastes the public line of
  a YubiKey (or of a Hello key on another PC). The App checks its shape and puts both lines in every
  script. In the first release the App does not sign with the YubiKey.
- The App can also publish a document and signature made elsewhere, unchanged. Without that, losing
  the Hello key's PC would leave the YubiKey able to sign but nothing able to publish.
- The next serial is one more than the highest of the bus's stored serial and any serial a host
  reports.
- **Before every Windows Hello prompt the App shows exactly what is about to be signed:** for a
  fleet, what changed since the last accepted one (hosts and coordinators added or removed,
  repositories, rules); for a command, the verb and the host.
- If a host reports a fleet serial the App did not publish, the App says so on the hosts page.
- The App writes the fleet file byte for byte to the worker host's schema.

### D. Remote control

- Four verbs only: pause, resume, drain, update. No arguments.
- One command names one host, expires within minutes and carries a random nonce. It is signed with
  the site key under its own namespace, `strugglebus-host-command`, so a fleet signature cannot be
  replayed as a command.
- One Windows Hello approval signs one command for one host.
- The App shows the result the host reports for that nonce, or "no answer".
- A frozen bus carries no commands. Blocking the host's service principal, and local commands on
  the host, still work.

## Open risks

The reviewer's main point: **the real authority here is the site key, not remote control.** Whoever
can sign a fleet can add a coordinator, and a coordinator runs code on every host. Remote control
only adds pause, drain and the timing of an update.

1. **The site key lives on one PC.** Mitigated by requiring a second signer before the first
   publish, and by the App being able to publish a document signed elsewhere.

   **The site key may also be usable by other programs in the operator's Windows session.** The App
   is an ordinary desktop program, not a packaged one, and as far as we know Windows scopes a Hello
   key to one program only for packaged programs. So assume another program running as the operator
   could ask Windows to sign with the key. Windows Hello would still prompt, but Hello proves the
   person is present, not what they meant to approve. This has to be tested before stage C is
   built. If it holds, the choices are to package the App so the key is scoped to it, or to accept
   the risk with these mitigations: the second signer, the App warning about a serial it did not
   publish, and hosts never moving to an older fleet.
2. **The enrolment code sits in a script file** on the operator's PC until it is used. It is single
   use, lasts 15 minutes and is bound to one host name.
3. **The App is not code signed.** The bootstrap script it embeds, and the release key built into
   it, are therefore only as trustworthy as the App download. Until code signing is possible, each
   App release should publish its SHA-256 signed with the project release key.
4. **Remote control is new authority.** It is limited to four verbs, cannot name a version, path or
   address, and cannot stop, restart or reconfigure a host.
5. **The operator command post** puts operator-authored messages on a channel other than #humans
   for the first time. It is limited to one message shape.

## Security review

u64-security, 24 Nov 2026, bus message 28470. Conditions on the bus and App side, and where each is
met in this document. The host side is in the worker host document, section 7.

| Condition | Met by |
|---|---|
| M1. Bind the fleet addition to the real install | Add a host, step 7; redeem keeps the request id |
| M2. Protect the script in transit | Add a host, step 4 |
| M3a. Show what is being signed | Coordinators and signing |
| M3b. Scope the site key to the App | **Open.** Risk 1; to be tested before stage C |
| M5. Harden the redeem call | Host enrolment code; Audit |
| M6. Keep a non-dedicated install visible | Hosts page |
| S1. Signed checksum for the App | Risk 3 |
| S2. The bus sets the fixed body | Operator command post |
| S3. Status shown as plain text | Hosts page |
| S4. Audit lines | Audit |

M4 (command parsing) and the answers on the release key and the dedicated account are the worker
host's.

## Not in the first release

- Signing with a YubiKey inside the App.
- Any of this in the web console or the Android app.
- Stopping, restarting, uninstalling or reconfiguring a host remotely.

## Decisions since the review

- **Key scoping is a condition, not a risk to accept** (u64-security, bus messages 28476 and
  28480). The mitigations detect and recover; they do not prevent a program in the operator's
  session from asking Windows to sign. So the App signs only when packaged, with a key made while
  packaged. The test that an unpackaged key is usable by another program, and that a key made
  before packaging stays unscoped, is still to be run; it needs the owner present.
- **Code signing.** The owner has ordered a Certum Open Source code-signing certificate. There is
  no self-signed stage: the App is packaged once, with that certificate, so the publisher and with
  it the site key's identity do not change. Until then the App is publish-only everywhere. A later
  move to a commercial certificate changes the certificate subject, so Microsoft's persistent
  identity guidance has to be set up while the old certificate is still valid, and "the site key
  survives a publisher change" is to be tested rather than assumed.
- **Remote control in the first release** (the owner's decision) therefore reaches a user once
  their App is packaged. Until then coordinators and signing are publish-only, with signing in the
  worker host's own tool.
- **Code and data are separate in "Add a host"**, as above.
- **Audit lines** (u64-security, bus message 28504): four flat nullable keys on every line, a
  request line for the command route, and nothing stated about a command's content, because the
  signed bytes on the channel are better evidence.

## What is built

On the bus `develop` branch, not released. Schema 24.

| Piece | Where |
|---|---|
| Host enrolment codes: mint and redeem | PR 284 |
| Site document store: publish and read the signed fleet | PR 285 |
| Operator command post: carry a signed host command | PR 286 |
| Audit lines for all three | PR 287 |

In the Windows App, on `main`, not released:

| Piece | Where |
|---|---|
| Worker hosts tab: each host's state, from its own status and the bus's last-seen time | PR 27 |
| Confirmation code and redeeming address for a host that joined with a code | PR 28 |
| Client calls for host codes, the document store and signed commands | PR 29 |
| The `sbhost-enrol.json` writer, held to the worker host project's vector byte for byte | PR 30, open |

Not built: the Add-host screen, the site key and signing, the coordinators screen, and the command
screen. The last three wait for the packaged App.

Worth knowing before a bus release: the deployment validation job does not run on pull requests to
`develop`, so the schema 24 pins in the deploy tooling have been checked by the test suite and by
hand, and get their first full check when `develop` is promoted to `main`.
