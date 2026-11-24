# Contracts

Files that more than one part of StruggleBus must agree on, byte for byte. Each
part's tests read them from here, so there is one copy and a change to a
contract is one pull request that every side's tests have to pass.

| Folder | What it pins | Written by | Read by |
|---|---|---|---|
| `host-enrol/` | `sbhost-enrol.json`, the data file a worker host's installer reads | the Windows App | the worker host's installer |

More arrive with the worker host: its status message, the signed fleet document
and signed host commands.

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
