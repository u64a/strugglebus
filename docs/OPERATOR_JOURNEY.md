# The operator's journey: from nothing to working hosts

A functional design. It says what a new person does, in order, to get from an empty network to
worker hosts running agent tasks, and what the Windows app must do at each step so that they
never edit a file, run a signing command, or need to know how the pieces fit.

It is written from the operator's side. How each piece works underneath is in the design
documents it links to. Where the app does not yet do what this says, the step says so under
**Gap**, and the gaps are collected at the end.

**Status:** draft for review, 28 November 2026, with the first round of review folded in
(u64-security, sbworkerhost-project and prox-manager: bus messages 29376 to 29378). Nothing here
is a decision until the owner has agreed it.

## Who this is for

One person, the **operator**, who runs a StruggleBus for themselves or a small team. They are
comfortable installing software and plugging in a security key. They are not expected to know
what a fleet document, a signer line or a namespace is, and they should be able to finish the
whole journey without learning.

## Principles

1. **The app does the heavy lifting.** If a step can be done by the app, the operator is not
   asked to do it by hand. No file is found, edited, copied or kept by the operator, except the
   two files that must physically travel to a new host.
2. **One journey, in order.** Each screen says what it is for, what comes before it, and what to
   do next. A step that cannot be done yet says what is missing and where to go.
3. **The operator's hardware key decides who may run code on the hosts.** Anything that changes
   which agents may task the hosts, or which PCs are hosts, is signed by a hardware key that
   asks for a touch and its PIN. The app holds no signing key of its own.
4. **Windows Hello confirms the person.** Every change the app sends to the bus is confirmed
   with Windows Hello, after the app has shown in words what will happen.
5. **The app says what you are approving.** Before a touch or a Windows Hello prompt, the
   operator reads the change in plain words. Warnings are part of that text, not hidden.
6. **A refusal is never a dead end.** When the app will not do something it says why, and what
   to do instead.
7. **The app never signs software.** The same hardware keys sign software releases. The app can
   only ever ask a key to sign the site's own fleet and commands to its hosts.

## What the operator needs before starting

- A machine to run the bus on (a small Linux container or Docker host on the local network).
- A Windows PC for the app.
- **Two hardware security keys** (YubiKeys), so that losing one does not lock the site out. A
  third kept somewhere safe is better.
- One or more Windows PCs to be worker hosts.

## The journey

### 1. Install the bus

The operator follows the [install guide](../bus/src/strugglebus/selfhost/INSTALL.md) for their
kind of machine. Two different codes are involved, and they are easy to confuse:

1. **The setup code**, shown once on the bus machine's own console. It is typed at the bus's
   web page (`/setup`), which may be opened from another PC, to set the operator's password.
   It is not to be shared, pasted into a chat, or written to a log.
2. **The enrolment for the app**, made afterwards in the signed-in web console
   (Administration, Devices). It is a block of text that lasts three minutes and is pasted into
   the app in step 2.

The operator should reach the bus by the HTTPS name it was installed with, and keep its
certificate authority: the app pins that authority in step 2 and will refuse another.

- **Done outside the app**, on the bus's own machine and in its web console. This is the one
  step that cannot start in the app, because the app has nothing to talk to yet.
- **Gap:** none in the app. The guide should end by pointing at step 2 and should say which of
  the two codes is which.

### 2. Install the app and enrol this PC

The operator downloads the Setup program from the project's releases, runs it, and pastes the
enrolment the bus's console gave them. The app then asks for Windows Hello and saves operator
access for this Windows account.

- **The app:** checks the enrolment, pins the bus's certificate authority, stores the device
  credential and the operator grant protected for this Windows account, and updates itself from
  then on.
- **Built.** See [the Windows README](../app/windows/README.md).
- **Gap:** after enrolling, the app opens on Monitor with no hint that a site still has to be set
  up. A first-run checklist (below) would carry the operator from here to step 3.

### 3. Register the hardware keys

**Admin, Security.** The operator registers each security key they own, spares included. The app
will not go on to step 4 with fewer than two.

There are three ways a key gets here, and the screen should offer them in this order:

| | For | What the operator does | State |
|---|---|---|---|
| a | **A new key**, never used for this before | Plugs it in, presses **Set up a new hardware key**, gives it a short name, enters the key's PIN and touches it when Windows asks | **Gap: not built** |
| b | **A key already set up on this PC** | Presses **Add this key** beside the key the app found | Built (pull request 107) |
| c | **A key set up somewhere else** | Chooses its public file | Built |

Whichever way, the app then shows the key's fingerprint, asks the operator to confirm it, asks
for Windows Hello, and adds the key to the site's signers.

**Setting up a new key (a), as proposed and reviewed by security (bus message 29377):**
- The app starts Windows' own `ssh-keygen`, by full path and only a copy validly signed by
  Microsoft (as for signing), to create the key on the security key:
  `ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:strugglebus-signing -O user=<short name> -N "" -f <new file>`
  - `verify-required`: the key asks for its PIN, as well as a touch, every time it signs.
  - `application=ssh:strugglebus-signing`: the same as the project's existing keys, so every
    site key is one kind and hosts treat them alike.
  - `resident`: the key's handle can be recovered from the security key itself. See below.
  - No passphrase on the file: it is only a handle, useless without the key, its touch and PIN.
- Windows shows its own security-key prompt. The app never sees the PIN.
- The two small files go in the operator's `.ssh` folder under a name the app makes from the
  short name. An existing file is never overwritten: the app refuses and asks for another name.
- The private half never leaves the security key.
- **The fingerprint:** for a key the app has just made there is nothing to compare it with. The
  app shows it, asks the operator to write it down or photograph it, and records it. The
  comparison that matters happens later, when each host reports the keys it pins.
- The app then adds the key as in (b), with Windows Hello.
- **Restore a key's file from the key.** Because the key is resident, the app also offers this
  (`ssh-keygen -K`) for a PC that has lost its `.ssh` folder or is new. Listing what is on a
  security key needs its PIN, so a finder without the PIN recovers nothing.
- A security key with no PIN set cannot be used. The app says so and points at Windows
  Settings, Accounts, Sign-in options, Security key.
- **Later, optional:** ask the key for an attestation and check that it chains to the maker's
  root, which proves it is real hardware and not a software stand-in. The key type alone does
  not prove that.

### 4. Say where the site's repositories are

**Admin, Add a host** (to move: see Gap). The operator lists the places hosts may work in, for
example one GitHub organisation. Every host is fenced to these, and an agent can only ever be
given repositories inside them.

- **Built**, and saved as soon as the box is left.
- **Gap:** it sits on the Add a host form, where a new operator does not expect a site-wide
  setting. It belongs on a **Site** card beside the hardware keys, with a line saying why it
  matters.

### 5. Start the site's fleet, or take over the one the hosts already run

**Admin, Who may task the hosts.** The fleet is the signed list of which PCs are worker hosts
and which agents may task them. The operator never sees it as a file.

- **A new site:** **Start this site's fleet.** The app makes an empty first fleet, the hardware
  key signs it, Windows Hello confirms, and it is published. Built (pull request 99).
- **A site whose hosts already run a fleet** that was kept somewhere else: **Take over the fleet
  my hosts run.** Each host offers the fleet it accepts; the app checks it against the registered
  keys and publishes it unchanged. Built (pull requests 102 and 103; needs bus 0.2.75).
- The app offers whichever applies and refuses the other with the reason.
- **Gap:** both buttons are shown together and the operator has to work out which is theirs. The
  app knows which applies (does any host report a fleet?) and should show only that one.

### 6. Add a worker host

**Admin, Add a host**, then on the new PC, then **Admin, Worker hosts.**

1. In the app: the operator names the PC, chooses its agent programs, and presses **Create code
   and save the installer and data file**. Two files are saved.
2. On the new PC: they copy the two files over, check the installer as the app's result box
   says, and run it as an administrator **at that PC's own screen and keyboard, not over SSH or
   a remote shell** (part of it runs as the new account, which fails over a remote shell). It:
   - installs the host under its own locked-down Windows account;
   - enrols it with the one-time code and prints a **confirmation code**;
   - **signs the agent programs in for the first time** (GitHub, Copilot and Claude, by a code
     typed at the tool's website or in a browser, as the operator chooses), and prints the
     host's **sign-in key fingerprint**, to compare later;
   - ends with an isolation check: if anything the new account could change runs as someone
     else, it says so, and the host shows an `isolation-weak` warning until that is fixed.
3. In the app: the host appears on Worker hosts. The operator presses **Check the code and add
   to the fleet**, compares the code with the one the installer printed, and on a match the
   hardware key signs the fleet that adds the host. On a mismatch the app shuts out whoever used
   the code.

Until step 3 is done the host waits, shown as "not in the fleet yet", and takes no work. On a
PC that already has a host, the new one installs beside it.

- **Built** (pull requests 75 to 86), apart from the gaps below.
- **Gap:** copying two files by hand is the last manual carry in the journey. It cannot be
  removed entirely (the new PC has no trust in anything yet), but the app could put both in one
  folder ready to copy, or on a USB stick, and say so.
- **Gap:** the comparison does not yet show who created the one-time code and when. Needs the
  bus (planned for 0.2.76).

### 7. Sign a host's agent programs in again

The installer signs the host's agent programs in the first time (step 6). This step is for
later: a token that expired, a licence that lapsed, or a program added afterwards.

**It matters more than it looks.** Once the installer finishes, the host's account can no
longer be signed in to at the keyboard or by remote desktop: that is what keeps it isolated. So
nobody can sign a program in again *as* that account by sitting at the PC. **Today the only way
is to reinstall the host.**

- **Gap: not built in the app, and the largest one.** The worker host's side is designed
  ([app-host-integration.md](../worker-host/docs/app-host-integration.md), section 4a) and the
  bus already carries what it needs (0.2.75). The app has to build:
  - **Signed commands to a host.** "Sign in to GitHub", "to Copilot", "to Claude", each signed by
    a hardware key for its own purpose (separate from the fleet's), naming one host, and good
    for at most ten minutes. The app cannot sign commands to hosts at all yet.
  - **Showing what the host answers:** the short code to type at the tool's website and when it
    expires, then done, or failed with the reason.
  - **For Claude:** the operator makes a token on their own PC. The app checks the host's
    sign-in key fingerprint against the one the installer printed, seals the token so that only
    that host can open it, and sends it. The token never passes through an agent or the bus in
    the clear. The host then shows the day it arrived, and warns when it is nearly a year old.

### 8. Authorise the agents that may task the hosts

**Admin, Who may task the hosts.** The operator types part of an agent's name, chooses it, says
which repositories it may have the hosts work in and where its notes live, and reads the
confirmation: the agent will be able to have **all** the fleet's hosts run code in those
repositories. The hardware key signs, Windows Hello confirms.

- **Built** (pull requests 88, 89, 95, 97).
- **Gap:** the confirmation is a plain Windows message box, so a broad location is marked in
  capitals rather than in red. An in-app review panel would do this properly, for every signed
  change.
- **Gap:** how and when the chosen agent was enrolled is not shown. Needs the bus (0.2.76).

### 9. Day to day

- **Hosts** page: what each host is doing now and over the last twelve hours. Built.
- **Channels**, **Monitor**, **Humans**, the bus log in Settings. Built.
- **Take away** an agent's authority, or **remove** a host: Who may task the hosts. Built. The
  app says that this is not instant, and names what is: block or retire the agent, or freeze
  agent access.
- **Updates:** the app updates itself; the bus and the hosts say in the app when one is waiting.

### 10. When something goes wrong

| What happened | What the operator does | State |
|---|---|---|
| **The app's PC is lost or stolen** | **First, from another enrolled device or the bus's web console: revoke that device (Admin, Devices) and replace the operator grant.** That PC held the device's enrolment and saved operator access; until it is revoked, whoever has the PC and its Windows sign-in is an operator. Then install the app on a new PC, enrol it, set up Windows Hello, get each hardware key's file back (from the key itself if it is a resident key; from a protected copy if it is not), register the keys as site signers again on that PC, and enter the site's repository locations again. The fleet is on the bus | Revoking and re-enrolling work today. **Gap:** restoring a key's file from the key (step 3); this procedure is not written down for the operator |
| A security key is lost | A finder also needs its PIN, and the key locks itself after a few wrong tries, so this is "replace it soon", not an emergency. Register its replacement on Security, then remove the lost one (never below two). Hosts already installed keep trusting it until it is removed on each host | Built in the app. **Gap:** removing it from the hosts needs a visit to each one |
| A security key is stolen and its PIN may be known | Remove it on Security at once. If any fleet change appears that you did not make, freeze agent access and check the fleet's history of serials | Built. **Gap:** the fleet's history is not shown in the app |
| A replacement key is added later | Registers it on Security. New hosts trust it. Hosts already installed do not, until re-pinned | **Gap:** the app does not yet show which hosts trust which keys. The hosts report it (bus 0.2.75); the app needs a warning where its set and a host's differ |
| A host's program sign-in lapses (an expired token, a lapsed licence, an old Claude token) | Signs it in again from the app (step 7) | **Gap:** not built; today only a reinstall |
| A host PC is lost or stolen | Removes it from the fleet (Who may task the hosts), then retires its agent and revokes its service principal on Admin. That shuts it off the bus | Built |
| A host PC is retired or reused | The same, off the bus. The PC itself still holds the host's Windows account, its scheduled task, its profile and its saved sign-ins | Off the bus: built. **Gap:** clearing the PC itself (stop the task, the processes, the profile, the account), which is the worker host's offboarding and is not built |
| A worker-host update goes wrong | Nothing. After three quick failures the host puts back the release it had and never retries the failed one. Hosts shows each host's release | Built |
| The wrong PC used a host code | The comparison in step 6 catches it and shuts it out | Built |
| An agent misbehaves | Blocks or retires it on Admin, Agents, or freezes agent access | Built |
| The bus's machine fails | Restores a tested backup of the **whole** deployment (the container, or the stopped Docker data volume), not the database alone: the bus's configuration and its web server's state are needed too. Then checks the HTTPS name still answers and that a signed-in read works, before going on | Outside the app. In the install guide |
| A bus update goes wrong | Follows the bus's own rollback procedure on its machine, with the matching release and the backup taken before the update. The app cannot roll the bus back | Outside the app. In the install guide |

## A first-run checklist

The largest single gap is that nothing ties these steps together inside the app. Proposed: a
**Set up this site** card on Admin, shown until every item is done, each item a link to its
screen:

1. Enrol this PC. *(done)*
2. Register two hardware keys.
3. Say where the site's repositories are.
4. Start the site's fleet. *(or: Take over the fleet your hosts run.)*
5. Add your first worker host.
6. Sign the host's agent programs in.
7. Authorise your first agent.

Each item shows done or not from what the app already knows (keys registered, a fleet on the
bus, hosts listed, agents listed). Nothing new is stored.

## Gaps, collected

| # | Gap | Where | Needs |
|---|---|---|---|
| 1 | Set up a new hardware key from the app, and restore a key's file from the key | Step 3 | The app; security has reviewed the proposal (29377) |
| 2 | A first-run checklist tying the steps together | All | The app |
| 3 | The site's repository locations on a Site card, not on Add a host | Step 4 | The app |
| 4 | Show only the fleet action that applies (start, or take over) | Step 5 | The app |
| 5 | Sign a host's agent programs in again from the app: signed commands to a host, the answer shown, a sealed token for Claude. **The largest gap: today it means a reinstall** | Step 7 | The app, to the worker host's design |
| 6 | A warning where the app's keys and a host's pinned keys differ | Step 10 | The app (the hosts report it from bus 0.2.75) |
| 7 | An in-app review panel for every signed change, instead of message boxes | Steps 5, 6, 8 | The app |
| 8 | Who created a host code and when; how an agent was enrolled | Steps 6, 8 | Bus 0.2.76, then the app |
| 9 | Security events on the bus for fleet and signer changes | All | Bus 0.2.76 |
| 10 | Adding or removing a trusted key on installed hosts without visiting each | Step 10 | The worker host; a two-key proposal exists (bus message 29211) |
| 11 | Recovery written down for the operator (lost PC, lost or stolen key, failed bus) | Step 10 | The manual |
| 12 | The fleet's history of serials, shown in the app | Step 10 | The app and the bus |
| 13 | Prove a new key is real hardware (attestation) | Step 3 | The app, later |
| 14 | Clear a retired host's PC: its account, task, profile and saved sign-ins | Step 10 | The worker host (offboarding) |

## Open questions for the owner

1. **A new key: resident or not?** A resident key can be recovered from the security key itself
   if the PC and its `.ssh` folder are lost, and uses one of the key's slots. A non-resident key
   is unusable if its small file is lost, even with the security key in hand. **Security
   recommends resident, and so do I,** with the app able to restore the file from a plugged-in
   key. The owner's existing keys' files are on one PC only; whether those three are resident is
   worth checking, because if they are not, a copy of the three small files should be kept
   somewhere safe.
2. **How many keys before going on?** Two is enforced today. Should the app ask for a third as a
   spare, or only suggest it?
3. **The first-run checklist:** shown on Admin only, or as the app's opening page until the site
   is set up?
4. **The order of work.** Suggested: gap 1 (new keys) and gap 2 (the checklist) first, because
   they are what a new user meets; then 4, 3 and 6. Gap 5 (signing a host in again) is the
   largest and, since review, the most pressing for a site already running: without it a lapsed
   sign-in means reinstalling the host. It may deserve to go ahead of the smaller ones.
