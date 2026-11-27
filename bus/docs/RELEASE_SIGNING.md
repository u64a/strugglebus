# Signed releases

Publishing a release is not enough to run code on a bus. From 0.2.72 an installed bus installs a
release only if its files are the ones named in a statement signed by one of the project owner's
hardware keys. Those keys are not held by GitHub, so write access to the releases repository
lets someone withhold or delay an update, and nothing more.

Before 0.2.72 the updaters checked only that a release's files matched hashes published in that
same release. That proves the files arrived intact. It does not prove who published them.

## What is signed

A short statement, as exact bytes with LF line ends:

```
strugglebus-bus-release 1
version 0.2.72
<sha256>  <file name>        one line per release file, sorted by name
```

It names all five release files: the wheel (which holds `install.sh` and every self-host
script), `requirements.lock`, `SHA256SUMS`, the manifest and the support archive (which holds
every maintenance helper). So everything that is run, or runs something, is covered.

The signature is an SSH signature in the namespace `strugglebus-bus-release`. The worker host
signs its releases with the same keys in a namespace of its own, so neither can be passed off as
the other.

The statement and its signature travel in the message of the release's annotated tag, after the
two lines that were there already. They are not a sixth release file: a bus that has not yet
updated to 0.2.72 insists on exactly five, and would refuse every later release and stick.

## Who checks, and when

The code that is already installed checks, before anything from the new release is run, unpacked
to be run, or imported.

| Install | Where | When |
|---|---|---|
| Self-hosted (Debian or Proxmox container, Docker) | `selfhost/fetch_release.py` | before any file is downloaded, then each downloaded file against the statement, before `install.sh` or any Docker file is touched |
| Ansible-deployed | the updater worker, `update_source.py` | when it prepares a release; it saves the statement beside the files as `release-statement.txt` |
| Ansible-deployed | the root installer, `maintenance_runtime.py` | again, itself, before it writes or runs anything. Root does not take the worker's word |

A release is refused when:

- its tag has no statement, or the signature is not a valid one by a pinned key;
- the signature was made for another purpose, without a touch, or without the key's PIN;
- the statement is for another version, or malformed;
- a file's hash is not the signed one, the release has a file the statement does not name, or
  lacks one it does;
- its version is not higher than the one running. The statement ties the files to the version,
  so an old release that was genuinely signed cannot be offered again as an update.

## The keys

The owner's three hardware keys are fixed in `fetch_release.py` as `RELEASE_KEYS`. That file is
installed root-owned, and the bus's service user cannot write it. Their fingerprints:

```
SHA256:xh5bC1DWKRzjLykESi8D5Qha6izhRNwkMJUyVMC2q2A
SHA256:I621GOi+pKy3XIbahS6mmqKCn7pVnQaubqPigdMTzus
SHA256:3bgt5AEYlZ4vvVtI9aVzPOTqBgwqyf0IYLEmNta9FpM
```

A different set of keys reaches a bus only in a release signed by one of these. To change them,
change `RELEASE_KEYS` and the fingerprints in `tests/test_release_signature.py` in a reviewed
pull request, and release it signed with a current key.

The key inside a signature only selects which pinned key to check against. It must equal one of
them byte for byte, application name included.

## How the check is made

In Python, in `fetch_release.py`, because that file also runs alone inside a plain Python
container that has no `ssh-keygen` and no third-party packages. It reads OpenSSH's signature
format, rebuilds what a hardware key actually signs (the hash of the key's application name, the
device's flags and counter, and the hash of OpenSSH's wrapper around the message's hash), and
verifies Ed25519 with code that follows the reference implementation in RFC 8032. It only
verifies; it never handles a secret.

The server's own paths load that same file, so there is one implementation, and hand the final
Ed25519 step to the `cryptography` library.

It is tested against:

- every valid and invalid case in Project Wycheproof's Ed25519 vectors;
- a real signature made with one of the owner's hardware keys (`tests/data/sk_signature/`), which
  `ssh-keygen -Y verify` is also asked about in the same test run;
- signatures of the same shape made with a stand-in key, each wrong in one way: another message,
  another key, another namespace, no touch, no PIN, a changed counter, trailing bytes, and so on.

## Publishing a release

One extra step for the owner, between promotion and the public mirror in
[RELEASE_PROMOTION.md](RELEASE_PROMOTION.md).

1. Print the statement for the five promoted files:

   ```sh
   python scripts/release_statement.py "$BUNDLE_DIR" --tag "$TAG" --output release-statement.txt
   ```

2. Read it. It should name the five files of this version and nothing else.

3. Sign it with a release key. This asks for the key's PIN and a touch:

   ```
   ssh-keygen -Y sign -f <release key> -n strugglebus-bus-release release-statement.txt
   ```

   The hardware key is plugged into Windows, so run this in PowerShell, not in WSL. It writes
   `release-statement.txt.sig`.

4. Give the signature to the publisher:

   ```sh
   python scripts/publish_public_release.py "$BUNDLE_DIR" ... --signature release-statement.txt.sig
   ```

   It works out the statement for the files itself and refuses to publish anything unless the
   signature is a valid one for it by a pinned key. An unsigned release cannot be published by
   mistake.

## Checking a release by hand

Anyone can check a published release with OpenSSH. Read the tag's message
(`gh api repos/<repository>/git/tags/<tag object sha> --jq .message`), save the statement (from
`strugglebus-bus-release 1` up to, not including, `-----BEGIN SSH SIGNATURE-----`) and the
signature block to two files, and:

```
ssh-keygen -Y verify -f allowed_signers -I owner -n strugglebus-bus-release -s statement.sig < statement
```

where `allowed_signers` lists the three keys with `namespaces="strugglebus-bus-release"`. Then
compare each file's SHA-256 with its line in the statement.

## The first signed release

0.2.72 is the release that carries this check. A bus on 0.2.71 or older takes it through the old
path, which does not check a signature, once. 0.2.72 is itself signed, so it can be checked by
hand as above before it is applied. From 0.2.72 on, every update is checked.

## What this does not cover

- A release mirror set with `RELEASE_API` in `update.conf` must also serve the tag
  (`git/ref/tags/<tag>` and `git/tags/<sha>`), or the self-hosted updater will refuse its releases.
- Someone with write access to the releases repository can still delete or withhold a release.
  That delays an update; it cannot run code.
- The first install is not covered. `INSTALL.md` has people download and run the installer, and
  that trusts GitHub as before.
