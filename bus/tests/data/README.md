# Test data

- `wycheproof_ed25519_test.json`: the Ed25519 verification vectors from Project Wycheproof
  (https://github.com/C2SP/wycheproof, `testvectors_v1/ed25519_test.json`), unchanged.
  Copyright Google LLC and the Wycheproof authors, Apache License 2.0.
- `sk_signature/message.txt` and `message.txt.sig`: a short message and its signature by one of
  the owner's hardware release keys, in the namespace `strugglebus-bus-release`. It lets the
  tests check a real FIDO-key signature, which no test can make. To remake it:
  `ssh-keygen -Y sign -f <release key> -n strugglebus-bus-release message.txt`
