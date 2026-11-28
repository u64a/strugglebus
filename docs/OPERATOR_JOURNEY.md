# The operator's journey: from nothing to working hosts

A functional design. It says what a new person does, in order, to get from an empty network to
worker hosts running agent tasks, and what the Windows app must do at each step so that they
never edit a file, run a signing command, or need to know how the pieces fit.

It is written from the operator's side. How each piece works underneath is in the design
documents it links to. Where the app does not yet do what this says, the step says so under
**Gap**, and the gaps are collected at the end.

**Status:** draft for review, 28 November 2026. Nothing here is a decision until the owner and
the reviewers have agreed it.

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

The operator follows the [install guide](../bus/src/strugglebus/selfhost/INSTALL.md). At the end
the bus's console shows a one-time code for enrolling the first operator device.

- **Done outside the app**, on the bus's own machine. This is the one step that cannot start in
  the app, because the app has nothing to talk to yet.
- **Gap:** none in the app. The guide should end by pointing at step 2.

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

**Setting up a new key (a), as proposed:**
- The app starts Windows' own `ssh-keygen` (by full path, Microsoft-signed, as for signing) to
  create an `ed25519-sk` key on the security key, requiring the PIN for every use
  (`verify-required`). Windows shows its own security-key prompt; the app never sees the PIN.
- The key's two small files are written to the operator's `.ssh` folder under a name the app
  chooses from the short name given, and are never overwritten.
- The private half never leaves the security key. The file beside it is only a handle: it does
  nothing without the key plugged in, touched, and its PIN.
- The app then treats it exactly like (b).
- **To decide:** whether the key is created as *resident* (discoverable), so that the handle can
  be recovered from the security key itself if the PC is lost, at the cost of using one of the
  key's limited slots. See "Open questions".
- A security key with no PIN set cannot be used. The app says so and points at Windows
  Settings, Accounts, Sign-in options, Security key.

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
   says, and run it as an administrator. It installs the host, enrols it with the one-time code,
   and prints a **confirmation code**.
3. In the app: the host appears on Worker hosts. The operator presses **Check the code and add
   to the fleet**, compares the code with the one the installer printed, and on a match the
   hardware key signs the fleet that adds the host. On a mismatch the app shuts out whoever used
   the code.

- **Built** (pull requests 75 to 86), apart from the gaps below.
- **Gap:** copying two files by hand is the last manual carry in the journey. It cannot be
  removed entirely (the new PC has no trust in anything yet), but the app could put both in one
  folder ready to copy, or on a USB stick, and say so.
- **Gap:** the comparison does not yet show who created the one-time code and when. Needs the
  bus (planned for 0.2.76).

### 7. Sign the host's agent programs in

The host's agent programs (Claude Code, GitHub Copilot CLI) each need signing in once, as a
person, before the host can take work.

- **Gap: not built in the app.** The worker host's side is designed
  ([app-host-integration.md](../worker-host/docs/app-host-integration.md), section 4a): a device
  code shown in the app for GitHub and Copilot, and a token sealed to the host for Claude. The
  bus already carries the fields (0.2.75). The app needs a **Sign in** action on the host's row
  that shows the code to type at the tool's website, and reports when it is done.
- Until then the operator signs in at the host's own keyboard, as its README says.

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
| A security key is lost | Removes it on Security (never below two, so add its replacement first). Hosts already installed keep trusting it until it is removed on each host | Built in the app. **Gap:** removing it from the hosts needs a visit to each one |
| A replacement key is added later | Registers it on Security. New hosts trust it. Hosts already installed do not, until re-pinned | **Gap:** the app does not yet show which hosts trust which keys. The hosts now report it (bus 0.2.75); the app needs a warning where its set and a host's differ |
| The app's PC is lost | Installs the app on another PC, enrols it, registers the keys again. The fleet is on the bus; nothing else was only on that PC | Works today. **Gap:** not written down for the operator |
| The wrong PC used a host code | The comparison in step 6 catches it and shuts it out | Built |
| An agent misbehaves | Blocks or retires it on Admin, Agents, or freezes agent access | Built |

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
| 1 | Set up a new hardware key from the app | Step 3 | The app; review by security before it is built |
| 2 | A first-run checklist tying the steps together | All | The app |
| 3 | The site's repository locations on a Site card, not on Add a host | Step 4 | The app |
| 4 | Show only the fleet action that applies (start, or take over) | Step 5 | The app |
| 5 | Sign a host's agent programs in from the app | Step 7 | The app, to the worker host's design |
| 6 | A warning where the app's keys and a host's pinned keys differ | Step 10 | The app (the hosts report it from bus 0.2.75) |
| 7 | An in-app review panel for every signed change, instead of message boxes | Steps 5, 6, 8 | The app |
| 8 | Who created a host code and when; how an agent was enrolled | Steps 6, 8 | Bus 0.2.76, then the app |
| 9 | Security events on the bus for fleet and signer changes | All | Bus 0.2.76 |
| 10 | Adding or removing a trusted key on installed hosts without visiting each | Step 10 | The worker host; a two-key proposal exists (bus message 29211) |
| 11 | Recovery written down for the operator (lost key, lost PC) | Step 10 | The manual |

## Open questions for the owner

1. **A new key: resident or not?** A resident key can be recovered from the security key itself
   if the PC and its `.ssh` folder are lost, and uses one of the key's slots. A non-resident key
   is unusable if its small file is lost, even with the security key in hand. The existing keys'
   files are on one PC only. Recommended: resident, with the app able to restore the file from a
   plugged-in key.
2. **How many keys before going on?** Two is enforced today. Should the app ask for a third as a
   spare, or only suggest it?
3. **The first-run checklist:** shown on Admin only, or as the app's opening page until the site
   is set up?
4. **The order of work.** Suggested: gap 1 (new keys) and gap 2 (the checklist) first, because
   they are what a new user meets; then 4, 3 and 6; then 5 and 7, which are larger.
