# Signing keys: the hardware keys that control the fleet

Hosts check SSH signatures on `fleet.toml` and `release.toml`. `tools/sign-config.ps1` signs and merges a change.
`install.ps1 -PinSigners` pins the keys on a host (section 7; a later `setup.ps1 -Only signers` will replace it).
Steps marked **(verify)** have not been tried on real hardware yet.

This is the runbook for:
- enrolling your hardware keys;
- setting up a PC to sign, including after every rebuild;
- signing a change;
- losing, replacing or removing a key.

Each section stands alone; jump to the one you need.

The examples use a YubiKey 5 series key, `ykman` and Win32-OpenSSH. Any FIDO2 key that `ssh-keygen` supports works
the same way.


> **`keys/allowed_signers` in this document is your site's signers file:** site-specific, kept with your deployment (for example in your fleet repository), not part of this repository. The project's own release keys are separate.

## 1. Why this exists, in plain words

Every worker host takes work only from the coordinators listed in `fleet.toml`, and installs only the software
release named in `release.toml`. Both files live in the site's fleet repository. Whoever can change them controls
every host.

Branch protection on `main` stops accidents, but it cannot stop an agent. Agents often work under the owner's
GitHub sign-in, so to GitHub an agent merging a PR looks exactly like the owner. So the hosts do not trust GitHub
for these files. They trust a **signature**:
- The signer signs each version of the file with a key that lives on a hardware key.
- Every host checks that signature before it uses the file.
- A signature needs the physical key, its PIN and a touch. No program on any machine can produce one, not even an
  agent running on the signer's own PC.

Agents can still *propose* changes (a new project, a new host, a new release) as PRs. Nothing changes on the hosts
until the signer signs.

## 2. The pieces

| piece | what it is | where it lives | secret? |
|---|---|---|---|
| The private key | created inside a hardware key, can never be copied off it | the hardware key (one per key) | yes, but unreachable |
| The FIDO2 PIN | unlocks the key for signing; 8 wrong tries in a row lock it for good (section 9) | the signer's head and password manager | yes |
| The key handle file | tells ssh-keygen which key on which device to use. Useless without the device and its PIN. It can always be read back off the device (section 5) | each signing PC's `~\.ssh`; optionally a backup copy in a password manager | no, but not published |
| The public key | `....pub`: what hosts check signatures against | your site's `keys/allowed_signers` (site-specific, kept with your deployment), and pinned on each host | no |
| The fingerprint | a short `SHA256:...` summary of a public key, for checking by eye | your own record (section 2.1), **and** a copy outside the repository (a password manager or a note on your phone), because setup checks the repository's list against it (section 7) | no |
| The pinned list on a host | `C:\ProgramData\strugglebus\allowed_signers`: the public keys this host accepts | each host; only an elevated (admin) prompt can change it | no |
| A signature | `fleet.toml.sig`, `release.toml.sig`: proof that one of the keys signed exactly these bytes | the repository, next to the file | no |

Every host stores its pinned list where only an elevated prompt can write. The host and its workers run *without*
elevation, so a worker cannot add a key of its own. The pinned list is never re-read from the repository after
setup: changing the repository's `keys/allowed_signers` affects only machines built afterwards, and setup shows the
fingerprints for the signer to confirm (section 7).

### 2.1 Your keys

Use one or more hardware keys. Two or three is better than one (section 3). Keep a record of each:

| label | model | firmware | fingerprint |
|---|---|---|---|
| **A** | `<model>` | `<firmware>` | `SHA256:EXAMPLEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| **B** | `<model>` | `<firmware>` | `SHA256:EXAMPLEbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` |

- Use `ed25519-sk`, resident, with PIN and touch on every signature (section 4.4).
- A key read back after a rebuild carries the comment `ssh:strugglebus-signing` (the application name), not the
  comment you gave it: the comment is not stored on the device. **Tell the keys apart by fingerprint** (or by a
  label stuck on each key).

### Names used everywhere

| name | value | why |
|---|---|---|
| key labels | **A**, **B**, ... | stuck on the keys and used in the key comments |
| application | `ssh:strugglebus-signing` | names the key on the device, so it never mixes with other SSH or FIDO keys there |
| key comment | e.g. `owner-key-A` | shows in `.pub` files and `allowed_signers`, so you know which physical key signed |
| principal | your choice, e.g. `owner` | the identity in `allowed_signers`. Hosts accept a signature from **any** principal the pinned list allows in that namespace, so several signers, or several keys under one name, both work |
| namespace for `fleet.toml` | `strugglebus-fleet` | a signature for one file can never be passed off as a signature for another |
| namespace for `release.toml` | `strugglebus-release` | as above |
| namespace for `baseline.toml` | `strugglebus-baseline` | reserved; hosts do not check a `baseline.toml` yet |

## 3. Where the keys live

A recommended split, if you have three:

- **A** (daily): on your keyring. Used for nearly every signature.
- **B** (home spare): somewhere safe at home, not with A.
- **C** (off-site spare): somewhere that is not home, for example a locked drawer at work or with someone you
  trust. It covers fire or burglary taking A and B together.

Enrol every key and list it on every host, so any one of them can sign. Lose one and you carry on with another
(section 9). With only one key, losing it means visiting every host by hand (section 9.3).

## 4. One-time enrolment of each key

Do this once per key, on one Windows PC, with the key plugged in. It takes about five minutes per key.

### 4.1 Before you start

- **YubiKey Manager CLI** (`ykman`): `winget install --id Yubico.YubiKeyManagerCLI --exact`. It installs to
  `C:\Program Files\Yubico\YubiKey Manager CLI\ykman.exe` and is **not** added to PATH. `ykman info` works from a
  normal prompt; every `ykman fido ...` command needs an **elevated** prompt on Windows
  (`ERROR: FIDO access on Windows requires running as Administrator`).
- **The right `ssh-keygen`.** Windows machines often have several:

  | path | version | use it? |
  |---|---|---|
  | `C:\Program Files\OpenSSH\ssh-keygen.exe` | Win32-OpenSSH from GitHub or winget | **yes**: talks to the key through Windows' own security-key support |
  | `C:\Windows\System32\OpenSSH\ssh-keygen.exe` | built into Windows | a fallback, also through Windows |
  | `C:\Program Files\Git\usr\bin\ssh-keygen.exe` | Git for Windows | **no** for signing: often first on PATH, but its security-key support is not reliable on Windows |

  So every command below uses the full path. In PowerShell:

  ```powershell
  $sk = 'C:\Program Files\OpenSSH\ssh-keygen.exe'
  ```

### 4.2 Check the key

```powershell
ykman info
```

- The firmware must be **5.2.3 or later** for `ed25519-sk` keys. On older firmware, use `-t ecdsa-sk` instead of
  `-t ed25519-sk` below; everything else is the same.
- Stick a label (A, B, ...) on the key.

### 4.3 Set the FIDO2 PIN (if it has none)

Easiest: **Settings → Accounts → Sign-in options → Security key → Manage**, touch the key, then **Add** (no PIN
yet) or **Change**. Or, in an elevated prompt: `ykman fido access change-pin`. A key already used for passkeys
has a PIN; keep it.

- Use at least 6 characters. The same PIN on all your keys is fine and easier to remember.
- Put it in your password manager.
- **8 wrong PINs in a row lock the FIDO2 part for good.** The only way back is a FIDO reset, which wipes every
  FIDO key on it, this one included. (After 3 wrong tries in a row you must unplug and replug it before trying
  again; that is normal.)

### 4.4 Create the signing key on the hardware key

```powershell
cd $env:USERPROFILE\.ssh
& $sk -t ed25519-sk -O resident -O verify-required -O application=ssh:strugglebus-signing -C owner-key-A -f <your key handle>
```

Run it from a normal, non-elevated prompt. When asked for a passphrase, press Enter twice. (Do not pass `-N ""`
from PowerShell: its handling of empty and quoted arguments to programs differs between versions, and a wrong
guess sets a passphrase of `""`.)

- `-O resident`: the key is stored on the device, so any PC can find it again later (section 5).
- `-O verify-required`: every signature needs the PIN as well as a touch.
- `-C owner-key-A`: change the label for each key.
- `-f <your key handle>`: the file name for the handle, for example one name per label.
- Windows shows its security-key dialog: enter the PIN, touch the key when it blinks.
- The file gets no passphrase: it holds only the handle; the PIN on the device is the protection.
- A **short** tap. A long touch on a key with Yubico OTP enabled also types a `cccc...` string into whatever window
  has focus (section 9.5).

This writes `<your key handle>` (the handle) and `<your key handle>.pub` (the public key).

### 4.5 Record it

```powershell
& $sk -lf <your key handle>.pub
```

This prints the fingerprint, e.g. `256 SHA256:EXAMPLE... owner-key-A (ED25519-SK)`. Then:

1. Add the key to your record (section 2.1).
2. Keep a copy of the fingerprints **outside** the repository: a password manager entry or a note on your phone.
   Setup compares the repository's list with it (section 7), so it must not come from the repository.
3. Optional backup: attach the handle file to a password manager entry. It is not needed, because the key can
   always be read back off the device (section 5.2), but it saves a step.

### 4.6 Test it

```powershell
'test' | Set-Content -NoNewline $env:TEMP\sigtest.txt
& $sk -Y sign -f <your key handle> -n strugglebus-test $env:TEMP\sigtest.txt
```

PIN and touch, then `sigtest.txt.sig` appears. Delete both test files.

### 4.7 After all keys: the repository list

`keys/allowed_signers` has one line per key:

```
owner namespaces="strugglebus-fleet,strugglebus-baseline,strugglebus-release" sk-ssh-ed25519@openssh.com AAAA...(from A's .pub)... owner-key-A
owner namespaces="strugglebus-fleet,strugglebus-baseline,strugglebus-release" sk-ssh-ed25519@openssh.com AAAA...(from B's .pub)... owner-key-B
```

- The first field is the principal. It can differ per line (one per signer), or several keys can share one.
- The middle part of each line is the `.pub` file's content minus its trailing comment.
- A line with no `namespaces=` may sign in any namespace. Hosts try every principal that may sign in the file's
  namespace until one verifies (`workerhost/signing.py`, `principals_for` and `verify`).

Commit it through a normal PR. Then pin the list on every existing host (section 7).

The namespaces say what a key may sign, and a signature is only accepted in the namespace it was made for, so a
signed `fleet.toml` can never pass as a release. List every namespace you will need before the first host pins the
list, so adding one later does not mean pinning again.

**Signing a release** is the same flow as a `fleet.toml` change. `python tools/make-release.py` opens a PR that
changes only `release.toml`. `tools/sign-config.ps1 -Pr <n> -KeyFile <your key handle>` signs it in the
`strugglebus-release` namespace, merges it, and creates the GitHub Release page. Hosts announce it at their nightly
check and apply it in their update window (`design.md` §10a). The serial rule is the same: exactly one more than
main's.

**A release in a shared repository** (the host's code in a folder, for example `worker-host/` in
u64a/strugglebus) is the same flow with the folder named:
- **Make it:** `python worker-host/tools/make-release.py --path worker-host`. The release goes to
  `worker-host/release.toml`; the notes list only commits that touched the folder.
  - **Each release there carries `moved_to` naming its own place** (taken from origin). A host remembers where its
    releases come from only through the release it has installed. Without the pointer, the next release would send
    it back to its fleet repository.
- **Sign it:** `pwsh -File worker-host\tools\sign-config.ps1 -Pr <n> -Path worker-host -Signers <your allowed_signers
  file> -KeyFile <your key handle>`.
  - Only `worker-host/`'s signed files may change in that PR.
  - The new signature is checked against the list you give, because the shared repository carries none. Hosts check
    against their own pinned copy either way.
  - No GitHub Release page is made: that repository's releases belong to its other products, and an App's updater
    reads them.
- **When the releases move there,** the first one continues the old place's count, because hosts refuse any serial
  not above the one installed. Use `make-release.py --continue-from <the old place's release.toml> --notes "..."`,
  then `sign-config.ps1 ... -FirstSerial <that serial>`.

## 5. Setting up a PC to sign (and after every rebuild)

Any PC can sign. Nothing on the hosts changes when a signing PC is rebuilt, because the key is on the device.

Keep signing PCs separate from worker hosts: signing keys never sit on hosts.

### 5.1 What the PC needs

- git, and `gh` signed in as an account that can merge to the fleet repository, to push the signature and merge.
- A clone of the repository.
- On Windows: Win32-OpenSSH in `C:\Program Files\OpenSSH` (section 4.1). On Linux: `openssh` and `libfido2` from
  the package manager.

### 5.2 Get the key handle back off the device

Plug in any of your keys. Open PowerShell **as administrator** (Run as administrator); this step does not work
without it.

```powershell
cd $env:USERPROFILE\.ssh
& 'C:\Program Files\OpenSSH\ssh-keygen.exe' -K
```

- PIN, then a short tap. When asked for a passphrase for the file, press Enter twice.
- It writes `id_ed25519_sk_rk_strugglebus-signing_<64 hex characters>` and the same with `.pub`. You may rename
  both to something short; then pass the handle to `sign-config.ps1` with `-KeyFile <your key handle>`.
- Only this step needs the elevated prompt. Signing works from a normal one.
- From a **non-elevated** prompt it fails with `Unable to load resident keys: invalid format`. Windows only lets
  administrators talk to a security key directly; a normal program goes through Windows' sign-in layer, which can
  create and use keys but cannot list them.
- The file it writes is owned by the administrator session. If a later non-elevated `ssh-keygen` complains about
  the file's permissions, take ownership of the two files or copy them out from a normal prompt.
  **(verify)**: not seen yet.
- If you have a backup of the handle file (section 4.5, step 3), copying it into `~\.ssh` works too.

**Linux:** `ssh-keygen -K` works there through libfido2, no root needed. **(verify)**: not tried yet. Windows is the
proven route.

### 5.3 Check it

```powershell
& 'C:\Program Files\OpenSSH\ssh-keygen.exe' -lf <your key handle>.pub
```

The fingerprint must match one in your record and in your copy outside the repository. The comment will be
`ssh:strugglebus-signing`, whichever key it is; the fingerprint tells you which. Then
`pwsh -File tools\sign-config.ps1 -Test -KeyFile <your key handle>` signs and verifies a test text against
`keys/allowed_signers`, so you know the whole chain works before you need it.

## 6. Signing a change (day to day)

Changes to `fleet.toml` (a new project, a new or rebuilt host, a coordinator removed) or `release.toml` (a new
release) arrive as PRs. To make one take effect:

```powershell
cd <your clone>
git pull
pwsh -File tools\sign-config.ps1 -Pr <number> -KeyFile $HOME\.ssh\<your key handle>
```

What the script does, step by step:

1. **Refuses** a PR that changes anything other than `fleet.toml`, `baseline.toml`, `release.toml` and their `.sig`
   files. Code never rides in on a config signature.
2. **Shows** each changed file's diff against `main`, and checks that the file's `serial` is exactly one more than on
   `main` (section 8).
3. **Asks** "sign?". Read the change; this is the moment that counts.
4. **Signs** the file's exact bytes as git stores them in the PR (not the copy in your working folder) with
   `ssh-keygen -Y sign` and the right namespace. The key asks for the PIN and blinks: touch it. A PR that changes
   two files asks twice.
5. **Verifies** the new signature against `keys/allowed_signers` from `main`, as a host would: good for any
   principal the list allows in that namespace.
6. **Commits** the `.sig` file to the PR branch and pushes it.
7. **Waits** for the checks, then merges. `-NoMerge` leaves the merge to you.
8. **Checks** the merged file and signature on `main` once more and prints the commit. Hosts pick up `fleet.toml`
   within 15 minutes (`wh fleet status --refresh` on a host does it at once), and each heartbeat then shows
   `fleet=<short sha>`.
9. **For a release:** creates the GitHub Release page (not with `-Path`, in a shared repository). Hosts read the
   signed `release.toml`, never the page.

### 6.1 By hand, if the script is broken

Run these from `cmd.exe`, **not PowerShell**, because PowerShell's `>` and `|` rewrite bytes and line endings and
the signature would not match:

```bat
cd <your clone, on the PR branch>
git cat-file blob HEAD:fleet.toml > %TEMP%\fleet.toml
"C:\Program Files\OpenSSH\ssh-keygen.exe" -Y sign -f %USERPROFILE%\.ssh\<your key handle> -n strugglebus-fleet %TEMP%\fleet.toml
"C:\Program Files\OpenSSH\ssh-keygen.exe" -Y verify -f keys\allowed_signers -I <principal> -n strugglebus-fleet -s %TEMP%\fleet.toml.sig < %TEMP%\fleet.toml
copy %TEMP%\fleet.toml.sig fleet.toml.sig
git add fleet.toml.sig && git commit -m "sign fleet.toml" && git push
```

`<principal>` is the first field of your key's line in `keys/allowed_signers`. The verify line must print
`Good "strugglebus-fleet" signature for <principal> with ED25519-SK key SHA256:...`. For `release.toml` use
namespace `strugglebus-release`. Then merge the PR on GitHub.

`.gitattributes` marks the signed files and `*.sig` as `-text`, so git never changes their line endings, and the
bytes on every machine are the bytes that were signed.

## 7. The pinned list on a host

**Today: `install.ps1 -PinSigners`.** On each host, in an **elevated** PowerShell, from the host's clone of this
repository:

```powershell
cd <the clone install.ps1 ran from>
git pull
pwsh -File install.ps1 -PinSigners
```

- It shows what is pinned now (if anything) and every fingerprint, comment and namespace it is about to pin, then
  asks you to type `yes`.
- **Compare each fingerprint with your copy outside the repository** (section 4.5) before typing it.
- It writes `C:\ProgramData\strugglebus\allowed_signers` byte for byte: owned by Administrators, writable by
  Administrators and SYSTEM only, readable by users. It checks the file reads back the same.
- Anything but `yes` changes nothing.

Until a host has a pinned list it keeps working on its `config.toml` pins; a `fleet.toml` on main is reported as
`fleet-cannot-verify` (detail `no-signers`) and not used. A release is reported as `release-cannot-verify` and not
applied.

- **Planned, with `setup.ps1`:** setup reads `keys/allowed_signers` from its clone, then checks it two ways, because
  the repository alone could have been changed:
  1. **With a hardware key.** Plug your daily key into the new host. Setup runs elevated, so it reads the key off the
     device (PIN, then a tap) and checks that its public key is in the list.
  2. **By eye.** Setup shows every fingerprint and comment. Compare them with your copy outside the repository
     (section 4.5) and confirm.

  Any mismatch: answer no, and setup stops.
- **Changed later** (a key or signer added or removed): edit `keys/allowed_signers` through a normal PR, merge it,
  then on **each host**, over RDP, in an **elevated** PowerShell:

  ```powershell
  cd C:\strugglebus-worker-host
  git pull
  pwsh -File install.ps1 -PinSigners      # later: pwsh -File setup.ps1 -Only signers
  ```

  It shows the old and new fingerprints and asks before writing `C:\ProgramData\strugglebus\allowed_signers`.

  It is deliberately manual. Who the fleet trusts can only change with hands on each machine, never through the
  repository.
- **Check what a host trusts:** `wh fleet status` lists the pinned fingerprints, comments and namespaces, the
  ssh-keygen it uses, and the fleet it has accepted (serial, commit, which key signed it, every coordinator and
  host). `wh fleet status --refresh` fetches and checks `fleet.toml` now instead of waiting up to 15 minutes.

## 8. Replay protection: the `serial`

Every signed file starts with `serial = <n>`. A host remembers the highest serial it has accepted and refuses
anything lower, logging `fleet-old`.

Without that, someone with push access could put back an *older* signed `fleet.toml`, for example one that still
lists a coordinator you removed, and its signature would still be good. `sign-config.ps1` requires each new
serial to be exactly one more than `main`'s (a new file starts at 1), so you never pick a number by hand.

## 9. When something goes wrong with a key

### 9.1 A key is lost or stolen

1. Carry on signing with another key; nothing is urgent. A finder still needs the PIN, and 8 wrong tries lock it
   for good.
2. Remove the lost key's line from `keys/allowed_signers` (PR, merge).
3. Pin the new list on each host (section 7).
4. Enrol a replacement key (section 4), add its line, and pin again on each host. You can do steps 2 and 4
   together so you visit each host once.
5. Update your record and your copy of the fingerprints outside the repository: remove the lost key, add the new
   one.

### 9.2 A key is broken, or its FIDO2 PIN is locked

Same as lost: remove it, enrol the replacement. A locked key can be reset with `ykman fido reset`, which wipes
every FIDO key on it; then enrol it again as if it were new (section 4). Its new public key is different, so it
needs a new line and a pin on each host.

### 9.3 All keys are lost

The hosts keep working on the last signed `fleet.toml` and release; only changes stop. Enrol new keys, put them in
`keys/allowed_signers`, and pin on each host by hand (section 7), confirming the new fingerprints. Hands on each
host is the right price for "change who the fleet trusts".

### 9.4 A signing PC was compromised

The key cannot be copied off the device, and every signature needs the PIN and a touch. A compromised PC can at
most:
- capture the PIN as you type it;
- or show you one change while signing another, at the moment you touch.

So:
1. Rebuild the PC.
2. Change the FIDO2 PIN on every key you used on it (`ykman fido access change-pin`).
3. Check the last few merged `fleet.toml` and `release.toml` changes on GitHub against what you meant to sign.

### 9.5 Troubleshooting

| you see | it means | do |
|---|---|---|
| `Key enrollment failed: invalid format` or `unknown key type` | the Git for Windows `ssh-keygen` ran | use the full path (section 4.1) |
| `ssh-keygen -K`: `Unable to load resident keys: invalid format` | the prompt is not elevated (5.2) | run it in PowerShell as administrator |
| `ERROR: FIDO access on Windows requires running as Administrator` | a `ykman fido ...` command in a normal prompt | elevated prompt, or the Settings screen for the PIN (4.3) |
| a string like `cccccbnrblk...` appears where the cursor is, after touching the key | a long touch fired Yubico OTP. Each code works once and is dead after the next one, so a pasted one is harmless | a short tap. If you never use Yubico OTP, turn it off in an elevated prompt: `ykman config usb --disable OTP` (FIDO2, passkeys and signing are unaffected) |
| `Couldn't sign message: device not found` | the key is not plugged in, or a different one than the handle file is for | plug in the right key; the fingerprint of the `.pub` says which |
| `incorrect passphrase supplied` or a PIN error | wrong PIN | careful: count the tries (4.3) |
| verify: `Could not verify signature` | the bytes changed after signing (PowerShell redirection, line endings, an editor) | sign the blob as in 6.1, from `cmd.exe` |
| verify: `no principal matched` or `not allowed` | the key is not in that `allowed_signers`, the wrong principal was given to `-I`, or the wrong namespace was used | check the namespace, the principal and which key signed |
| host log `fleet-unsigned` | a `fleet.toml` on `main` has no valid signature | sign it (section 6); the host keeps the last good list meanwhile |
| host log `fleet-old` | the serial went backwards | someone put back an old file; investigate, then sign a new serial |
