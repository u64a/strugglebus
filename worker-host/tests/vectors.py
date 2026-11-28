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
NAMES = ("host-command", "fleet", "host-enrol", "host-status", "host-events", "sealed-signin")

PINNED = {
    "fleet/allowed_signers": "ce7633fea544aca440d9e3bf8f8e59bacbfc67f3883109af2f9883e4e18a6e84",
    "fleet/compose/add-coordinator-after.toml": "fa5d47f91a4607fe580d2eb9a51f55b4ad5fb660e9ddfba8063735fa2788866d",
    "fleet/compose/add-coordinator-broad-after.toml": "2a92205d16792f8d1fba65e081ed21b4c6d12f2c4a99d150091454089fd71558",
    "fleet/compose/add-coordinator-no-engine-after.toml": "037e9a8d27a20fac831209451cc79fa4c68f8257499392e1c1db124f2986f28e",
    "fleet/compose/coordinators.json": "0f8a822ee18842b7e8ccea5d766e92161cb26a03a09056a2c30faf9a2f0f998e",
    "fleet/compose/hand-edited.toml": "ba9da1b1bfeed4b05274d5eaeaf6a7e5b1726263484f1475f91b3aa6c350d4ce",
    "fleet/compose/not-a-fleet.json": "6120834a486958d06f8165caddf424478052036cfed75e0729717d3bf5949a8b",
    "fleet/compose/not-fleet-release.toml": "3d2e5ca076750716bdad8165a65a0edbb7535987a93becd621f3b291b69ae411",
    "fleet/compose/not-fleet-statement.txt": "0e5cc480877428ad3bf99402d37e5d2b2671842df8103d4d82de2bd22518002a",
    "fleet/compose/remove-coordinator-after.toml": "b4c290ac70f06766ec59f1c09e7315d50a7b31c65665e22f4dda0418a84c6f35",
    "fleet/compose/remove-host-after.toml": "457e8cec1a00a4936bb5dee7616aae84bc5534c48bce651b7b5c5b52387c9a5d",
    "fleet/compose/two-each.toml": "72e8618edefcc36a8de298479ade713ba801f98a3784fedf9d8310ac9fdf48f5",
    "fleet/compose/after.toml": "4d3204e326ae634fa138b626259316d6c40b428e279d8b413be4cb683d03037e",
    "fleet/compose/before.toml": "bc1ace56aca1c25b0431de9d0a0cc7425b2eb8f76a46acbae24825ee5184fc16",
    "fleet/compose/duplicate-id.toml": "9628751f094bc74a2a97efe48002fffbb1f6344bf3063996e5ee11f510d8d968",
    "fleet/compose/duplicate-name.toml": "5b8090ed8c1993eb700b14eed9faf74118abd8315f263754c0692ec742a33512",
    "fleet/compose/expected.json": "1c7cdb4797905e461c830cc430330f4b700d19ff52475b2bd71ff620c5f572a4",
    "fleet/compose/plain-ed25519.sig": "9827c7ef1ca0847daa6766015d0e7646148a29ab3bc8901bfc15f81a11ac5e70",
    "fleet/compose/serial-missing.toml": "e84c5aba79bb43de44d301937ac9a4d0d38df52886052e29d1562df432fc83e3",
    "fleet/compose/serial-twice.toml": "ac3e34c8b0583e73dc3b06c70112161aa841218dc99349abd75cfacc9d91542f",
    "fleet/compose/sk-touch-only.sig": "8212ff6ced555eb3acbb9cd37005eadca0c4f2add72a1d09eec2b98f55d126a3",
    "fleet/compose/sk-touch-pin.sig": "30ee0bc2339dd464f93ec6589e9804dbb444cc187b171bd83986baeaf49c7b1e",
    "fleet/compose/start-bare.toml": "b3dbd5aee8fdb99d3feaab96088f7e99e89d6ce663ad3f95f169f641e5895fae",
    "fleet/compose/start-owner.toml": "0bc05161ba4685f83c6884841c2209ac774d0af731c832c0d9a3990ea8d35554",
    "fleet/compose/start-then-coordinator.toml": "8462665db2e6667f0a61f10456db2fa9c9374d1f9cdc3e5f531367c3329c28d8",
    "fleet/compose/start-then-host.toml": "ab45a64002c6cda488504e6bd14dd66a6ef21267ee990569a5dbfd4802ad8590",
    "fleet/compose/start.json": "291f95fc70f838f3adf7482e73d2d53185fec0cc125e2e77535d827356f02567",
    "fleet/compose/unknown-table.toml": "e1958803207854461e5d2507f6749ea7056a5518868b5c32da0fe78a0e910219",
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
    "host-events/batch-21-events.json": "fd6829da23ad0ef0b08dcbe31b3e4892552cbd5098c274392d892e20a8a7dac6",
    "host-events/batch-free-text.json": "57c7d53c20999b248d6bcd54e7c176d02f7e3b6b588d88490201e66a460cf4d7",
    "host-events/batch-good.json": "5c44f56c43fecdef291402af215d66b2ba271a66bddc07561181634c935080ce",
    "host-events/batch-unknown-field.json": "1d18126b7320e48773ade472911b546e87ce6f74a7dc6eff2e0791b8c1a24554",
    "host-events/batch-unknown-type.json": "0635459985075b2b1347a8bde778a99f2be11f493ce5b1a47a4436e276b46bc5",
    "host-events/batch-wrong-agent.json": "7d28fc908d328aabd9b7d19c1940436dd279071a4d9ed79efc3575a8b72b3c9a",
    "host-events/expected.json": "fdded42ff4c8d4eee4654a8917cc5c143edf23c577ec7400cff0d3389be5fa55",
    "sealed-signin/vector.json": "9933734beb37fbd9d90dab20e30e86684cd5310f274f1e878a5b502130aad8df",
    "host-status/sample-v2.json": "f0377cc9142d2c9a2382d18ae9d9c5eaeb2d89a5815077964f45b238fa1e3ca3",
    "host-status/snapshot-v2-device.json": "4ede2b330023e0179b2a62ebbf577d8dcacd8ef025f19ea354a7755faaee0e3a",
    "host-status/snapshot-v2.json": "dfdd19e0aa5ae9e4a02ce41eb192067c1df17030894f7beca9388eb352d55555",
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
