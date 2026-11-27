"""Where the shared contract vectors are: the monorepo's top-level `contracts/<contract>/` (read by the App's, the bus's
and the host's tests alike), else this repository's own copy in tests/data/vectors (one folder for all of them).

In the monorepo every file read is checked against its pinned SHA-256 first (contracts/README.md, "Tests pin the
hash"): a contract changed by accident fails here loudly instead of quietly agreeing with itself. A deliberate
change updates the pin in the same pull request."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "tests" / "data" / "vectors"
CONTRACTS = ROOT.parent / "contracts"
NAMES = ("host-command", "fleet", "host-enrol", "host-status")

PINNED = {
    "fleet/allowed_signers": "ce7633fea544aca440d9e3bf8f8e59bacbfc67f3883109af2f9883e4e18a6e84",
    "fleet/expected.json": "5fd7b05843345af4c6438aba36a8f7ac5db8eb36a457926892c691597665bfc8",
    "fleet/fleet-changed-byte.toml": "0c8cb19ff53329b19d1cadef4ddfd08453533d16a8573fc006ef905d61d109dc",
    "fleet/fleet-changed-byte.toml.sig": "c7a16db52385e014545cb3f9a48f660815480f861a21adbaff366960de93c377",
    "fleet/fleet-wrong-namespace.toml": "bc1ace56aca1c25b0431de9d0a0cc7425b2eb8f76a46acbae24825ee5184fc16",
    "fleet/fleet-wrong-namespace.toml.sig": "2da7be26bac8f7daa58f965b55afa62550c6fd3e9b5c85e59f397428cc50fe73",
    "fleet/fleet.toml": "bc1ace56aca1c25b0431de9d0a0cc7425b2eb8f76a46acbae24825ee5184fc16",
    "fleet/fleet.toml.sig": "c7a16db52385e014545cb3f9a48f660815480f861a21adbaff366960de93c377",
    "host-command/allowed_signers": "ce7633fea544aca440d9e3bf8f8e59bacbfc67f3883109af2f9883e4e18a6e84",
    "host-command/cmd-bad-verb.json": "4903f095e401b6a1a1a227f05f61f1f80363602f536ba2c394664781564888d2",
    "host-command/cmd-bad-verb.json.sig": "4654a31f15ec8be721eca2fb5256ecac5cec10beb003889a352cef78903819e8",
    "host-command/cmd-duplicate-key.json": "6abccbb02715cb52fcbb4acbe8dced669fb30e8487caec1e7639254c806ba894",  # gitleaks:allow
    "host-command/cmd-duplicate-key.json.sig": "af6929408acf02b03be741be8e1a41b81d3e2193fe6eb5302ddfa0cb70348d86",  # gitleaks:allow
    "host-command/cmd-expired.json": "759d5429adf499cbbef682a7465308d4cc2095e63861df05cddf56725268f818",
    "host-command/cmd-expired.json.sig": "f0d7fac6fd60e10d8d04ba343c8c52598f6de6175f83d14b6fbfbb6dd90a95eb",
    "host-command/cmd-fleet-namespace.json": "327da762176918480b67dc11b493458e211c0bb521ee9e5911d9d8071d51db50",
    "host-command/cmd-fleet-namespace.json.sig": "264a47cc6cf171a9af4d56df0628352d795cad4dfa7103ce2e00a2907b37912d",
    "host-command/cmd-from-future.json": "e978caa57cc9c2861665e66954b3978bde63ffba9aac8e51360a9809269537d3",
    "host-command/cmd-from-future.json.sig": "33564078222b72b9d8297c2134ecdfb525c2fa45e09181183b4eace1e859a9de",
    "host-command/cmd-other-host.json": "2d7f8e4615b8373a1f86fea48f75e242c3f69b3d2469ce6acdb98919a06c303b",
    "host-command/cmd-other-host.json.sig": "d8b48043801af60948fceb46b0f42140e472aa1504f7145360a5b3aa66541623",
    "host-command/cmd-pause.json": "0cd70865791f275bf3854ae706510629d1e753a0f903f36d22f2b8636e0e72db",
    "host-command/cmd-pause.json.sig": "58489e20288b15cdb4763bd10fce9ee5f220d2eba8433206cd6652b33edcfd1a",
    "host-command/cmd-replayed.json": "0cd70865791f275bf3854ae706510629d1e753a0f903f36d22f2b8636e0e72db",
    "host-command/cmd-replayed.json.sig": "58489e20288b15cdb4763bd10fce9ee5f220d2eba8433206cd6652b33edcfd1a",
    "host-command/cmd-too-long.json": "fd42b85bcc5bd68838f47e57d001115760c2dc30a044a1bdfa721dd272108db8",
    "host-command/cmd-too-long.json.sig": "eddcc546bc07ddec8be27d452fee54efedef926af97f76bec53c37f0d1ee7929",
    "host-command/cmd-unknown-field.json": "1ec4939c20296574c444ecb0fc97fca90738f7b3ed07888bbeae8c8983bfc82e",
    "host-command/cmd-unknown-field.json.sig": "6e961e61b162f28fa57c248d8432961001ed4b82c4a7bf699209baff7a7a0373",
    "host-command/cmd-update.json": "adab7cf91cd43f91c7b1ad48efdc01e2ed6948a96d011f05a47f61debbbe4d18",
    "host-command/cmd-update.json.sig": "2632b35e593ae3c7ed4e410f2bbc2312bc78e2764f98f444f5de5ded693f33a0",
    "host-command/expected.json": "b785b0887fe90390d2795d611a884dc1748ddb681c91a002b30d18b571761920",
    "host-enrol/sbhost-enrol.json": "42d75e14b586793374addfa1e22f1627bb887fea0eb88af7f16fdb06d61e9782",
    "host-status/sample-v2.json": "f0377cc9142d2c9a2382d18ae9d9c5eaeb2d89a5815077964f45b238fa1e3ca3",
    "host-status/snapshot-v2-device.json": "aadb5bca41c1dac6c7538a8aefe3f99951928be07016360f9965d5b49ce93d4a",
    "host-status/snapshot-v2.json": "07261a78e8724a173d0d9482db4ed109711dd29a8d012e15ffd134220036f2fb",
}


def path(contract: str, name: str) -> Path:
    assert contract in NAMES, contract
    folder = CONTRACTS / contract
    if not folder.is_dir():
        return LOCAL / name
    p = folder / name
    want = PINNED.get(f"{contract}/{name}")
    assert want is not None, f"contracts/{contract}/{name} is not pinned in tests/vectors.py"
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    assert got == want, f"contracts/{contract}/{name} changed: sha256 {got}, pinned {want}"
    return p
