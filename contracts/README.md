# Contracts

Files that more than one part of StruggleBus must agree on, byte for byte. Each
part's tests read them from here, so there is one copy and a change to a
contract is one pull request that every side's tests have to pass.

| Folder | What it pins | Written by | Read by |
|---|---|---|---|
| `host-enrol/` | `sbhost-enrol.json`, the data file a worker host's installer reads | the Windows App | the worker host's installer |
| `host-command/` | signed host commands (pause, resume, drain, update): good and bad documents with their SSHSIG signatures, the test signer, and `expected.json` with the result for each, in order | the Windows App (signs) | the worker host (`worker-host/workerhost/commands.py`) |
| `fleet/` | the signed fleet document: a good one, one changed byte, one signed in the wrong namespace, the test signer, and `expected.json` | the Windows App (publishes) | the worker host (`worker-host/workerhost/fleet.py`) |

The worker host's tests pin every file here by SHA-256 (`worker-host/tests/vectors.py`). The signatures were made
with a throwaway RSA-2048 key, as a Windows Hello key would make them, and its private half was discarded.

## Rules

- **Nothing here is reformatted.** `.gitattributes` marks the folder `-text`, so
  git never changes a line ending. Do not run a formatter over it.
- **Tests pin the hash.** A test that reads a contract file checks its SHA-256
  first, so a file changed by accident fails loudly instead of quietly
  agreeing with itself.
- **A contract changes on every side at once.** Change the file, the code that
  writes it and the code that reads it in the same pull request.
- **No secrets.** Keys here are test keys whose private halves were discarded.
  A signer line holds a public key.
