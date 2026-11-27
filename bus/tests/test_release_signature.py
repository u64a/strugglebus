"""The publisher's signature on a release, as the installed updaters check it."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from release_signing import NAMESPACE, ReleaseKey, packed, statement_for

DATA = Path(__file__).resolve().parent / "data"
KIT = Path(__file__).resolve().parents[1] / "src" / "strugglebus" / "selfhost"


def _load():
    spec = importlib.util.spec_from_file_location("fetch_release_signature", KIT / "fetch_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fetcher = _load()
KEY = ReleaseKey()
OTHER = ReleaseKey()
FILES = {"requirements.lock": b"lock\n", "strugglebus-0.3.0-py3-none-any.whl": b"wheel", "SHA256SUMS": b"sums\n"}
STATEMENT = statement_for("0.3.0", FILES)


def signer(signature: str, message: bytes = STATEMENT.encode(), **options) -> str | None:
    return fetcher.signer_of(signature, message, keys=(KEY.blob,), **options)


# ---- Ed25519 ---------------------------------------------------------------------------------

def _wycheproof():
    vectors = json.loads((DATA / "wycheproof_ed25519_test.json").read_text(encoding="utf-8"))
    for group in vectors["testGroups"]:
        for case in group["tests"]:
            yield pytest.param(group["publicKey"]["pk"], case, id=f"tc{case['tcId']}")


@pytest.mark.parametrize(("public", "case"), _wycheproof())
def test_ed25519_agrees_with_the_wycheproof_vectors(public: str, case: dict):
    verified = fetcher.ed25519_verifies(
        bytes.fromhex(public), bytes.fromhex(case["msg"]), bytes.fromhex(case["sig"]),
    )
    # "acceptable" cases use weak public keys, where either answer is allowed. Release keys are
    # pinned, so a weak key cannot be offered here at all.
    if case["result"] != "acceptable":
        assert verified == (case["result"] == "valid"), case["comment"]


def test_the_wycheproof_file_is_the_whole_suite():
    vectors = json.loads((DATA / "wycheproof_ed25519_test.json").read_text(encoding="utf-8"))
    results = [case["result"] for group in vectors["testGroups"] for case in group["tests"]]
    assert vectors["algorithm"] == "EDDSA" and len(results) == vectors["numberOfTests"] > 200
    assert results.count("valid") > 100 and results.count("invalid") > 50


def test_ed25519_agrees_with_the_cryptography_library_on_fresh_signatures():
    for index in range(8):
        key = ReleaseKey()
        message = bytes([index]) * (index * 13)
        signature = key._private.sign(message)
        assert fetcher.ed25519_verifies(key.public, message, signature)
        assert not fetcher.ed25519_verifies(key.public, message + b"x", signature)
        assert not fetcher.ed25519_verifies(OTHER.public, message, signature)


@pytest.mark.parametrize("public, signature", [
    (b"\x00" * 31, b"\x00" * 64),
    (b"\x00" * 32, b"\x00" * 63),
    # y is not below the field prime.
    (b"\xff" * 32, b"\x00" * 64),
])
def test_ed25519_refuses_malformed_keys_and_signatures(public: bytes, signature: bytes):
    assert not fetcher.ed25519_verifies(public, b"message", signature)


# ---- The OpenSSH wrapper and the hardware key ------------------------------------------------

def test_a_statement_signed_by_a_release_key_names_its_signer():
    assert signer(KEY.sign(STATEMENT.encode())) == fetcher.key_fingerprint(KEY.key_blob)


PINNED_FINGERPRINTS = [
    "SHA256:xh5bC1DWKRzjLykESi8D5Qha6izhRNwkMJUyVMC2q2A",
    "SHA256:I621GOi+pKy3XIbahS6mmqKCn7pVnQaubqPigdMTzus",
    "SHA256:3bgt5AEYlZ4vvVtI9aVzPOTqBgwqyf0IYLEmNta9FpM",
]


def test_a_real_hardware_key_signature_verifies_with_the_pinned_keys():
    """A fixture signed once with one of the owner's real release keys (see data/README.md)."""
    message = (DATA / "sk_signature" / "message.txt").read_bytes()
    signature = (DATA / "sk_signature" / "message.txt.sig").read_text(encoding="utf-8")

    signed_by = fetcher.signer_of(signature, message)

    assert signed_by in PINNED_FINGERPRINTS
    assert fetcher.signer_of(signature, message + b"\n") is None
    # Signed for bus releases, so it is no use in the worker host's namespace, or the reverse.
    assert fetcher.signer_of(signature, message, "strugglebus-release") is None


def test_the_real_fixture_signature_can_never_pass_as_a_release():
    """It is a genuine signature by a release key, in the live namespace, so this must hold for good."""
    message = (DATA / "sk_signature" / "message.txt").read_text(encoding="utf-8")
    signature = (DATA / "sk_signature" / "message.txt.sig").read_text(encoding="utf-8")
    assert fetcher.signer_of(signature, message.encode()) is not None

    for version in ("0.2.72", "0.3.0", "1.0.0"):
        for tag_message in (message + signature, "Strugglebus public release mirror v1\n{}\n" + message + signature):
            with pytest.raises(fetcher.Problem, match="the release is not signed by its publisher"):
                fetcher.signed_digests(tag_message, version)
    assert not message.startswith(fetcher.STATEMENT_HEADER)
    assert fetcher.STATEMENT_HEADER + "\n" not in message


def test_the_pinned_keys_are_the_owners_three_hardware_keys():
    fingerprints = [fetcher.key_fingerprint(base64.b64decode(key)) for key in fetcher.RELEASE_KEYS]
    assert fingerprints == PINNED_FINGERPRINTS


REFUSED = {
    "another message": lambda: (KEY.sign(b"something else"), {}),
    "a key that is not pinned": lambda: (OTHER.sign(STATEMENT.encode()), {}),
    "another purpose (the worker host's namespace)": lambda: (
        KEY.sign(STATEMENT.encode(), namespace="strugglebus-release"), {},
    ),
    "a namespace that only starts the same": lambda: (
        KEY.sign(STATEMENT.encode(), namespace=NAMESPACE + "-x"), {},
    ),
    "no touch": lambda: (KEY.sign(STATEMENT.encode(), flags=0x04), {}),
    "a touch but no PIN": lambda: (KEY.sign(STATEMENT.encode(), flags=0x01), {}),
    "the weaker hash": lambda: (KEY.sign(STATEMENT.encode(), algorithm=b"sha256"), {}),
    "a signature of another type": lambda: (
        KEY.sign(STATEMENT.encode(), signature_type=b"ssh-ed25519"), {},
    ),
    "a plain key of the same value, not a hardware key": lambda: (
        KEY.sign(STATEMENT.encode(), key_blob=packed(b"ssh-ed25519", KEY.public)), {},
    ),
    "the same key under another application name": lambda: (
        KEY.sign(STATEMENT.encode(), key_blob=packed(b"sk-ssh-ed25519@openssh.com", KEY.public, b"ssh:")), {},
    ),
    "bytes after the signature": lambda: (KEY.sign(STATEMENT.encode(), trailing=b"\x00"), {}),
    "a counter changed after signing": lambda: (
        _with_device(KEY.sign(STATEMENT.encode()), bytes([0x05, 0, 0, 0, 8])), {},
    ),
    "flags raised after signing": lambda: (
        _with_device(KEY.sign(STATEMENT.encode(), flags=0x01), bytes([0x05, 0, 0, 0, 7])), {},
    ),
    "not a signature at all": lambda: ("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----", {}),
    "no armour": lambda: ("AAAA", {}),
    "a cut-off signature": lambda: (_truncated(KEY.sign(STATEMENT.encode())), {}),
    "base64 that is not base64": lambda: (
        "-----BEGIN SSH SIGNATURE-----\n!!!!\n-----END SSH SIGNATURE-----", {},
    ),
}


def _blob(signature: str) -> bytes:
    return base64.b64decode("".join(signature.splitlines()[1:-1]))


def _armour(blob: bytes) -> str:
    return "-----BEGIN SSH SIGNATURE-----\n" + base64.b64encode(blob).decode() + "\n-----END SSH SIGNATURE-----"


def _with_device(signature: str, device: bytes) -> str:
    """Swaps the flags and counter the hardware key reported, leaving the signature as it was."""
    return _armour(_blob(signature)[:-5] + device)


def _truncated(signature: str) -> str:
    return _armour(_blob(signature)[:-20])


@pytest.mark.parametrize("what", sorted(REFUSED))
def test_a_signature_is_refused_for(what: str):
    signature, options = REFUSED[what]()
    assert signer(signature, **options) is None


def test_the_wrapper_version_must_be_one():
    blob = bytearray(_blob(KEY.sign(STATEMENT.encode())))
    blob[9] = 2
    assert signer(_armour(bytes(blob))) is None
    blob[9] = 1
    blob[0] = ord("X")
    assert signer(_armour(bytes(blob))) is None


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_ssh_keygen_agrees_about_the_real_hardware_signature(tmp_path: Path):
    """The same real signature, checked by OpenSSH itself against the same three keys."""
    folder = DATA / "sk_signature"
    signers = tmp_path / "allowed_signers"
    signers.write_text("".join(
        f'owner namespaces="{NAMESPACE}" sk-ssh-ed25519@openssh.com {key}\n'
        for key in fetcher.RELEASE_KEYS
    ), encoding="utf-8")

    def check(namespace: str, message: bytes) -> int:
        return subprocess.run(  # noqa: S603, S607 - fixed program and arguments
            ["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "owner", "-n", namespace,
             "-s", str(folder / "message.txt.sig")],
            input=message, capture_output=True, check=False, timeout=30,
        ).returncode

    message = (folder / "message.txt").read_bytes()
    assert check(NAMESPACE, message) == 0
    assert check(NAMESPACE, message + b"\n") != 0
    assert check("strugglebus-release", message) != 0


# ---- The statement ---------------------------------------------------------------------------

def digests(message: str, version: str = "0.3.0") -> dict[str, str]:
    return fetcher.signed_digests(message, version, keys=(KEY.blob,))


def refusal(message: str, version: str = "0.3.0") -> str:
    with pytest.raises(fetcher.Problem) as raised:
        digests(message, version)
    assert raised.value.code == fetcher.INVALID
    return str(raised.value)


def test_the_statement_is_the_version_and_one_hash_per_file_sorted_by_name():
    assert fetcher.release_statement("0.3.0", {name: hashlib.sha256(data).hexdigest().upper() for name, data in FILES.items()}) == STATEMENT
    assert STATEMENT.splitlines()[:2] == ["strugglebus-bus-release 1", "version 0.3.0"]
    assert [line.split("  ")[1] for line in STATEMENT.splitlines()[2:]] == sorted(FILES)


def test_a_signed_tag_message_gives_the_hash_of_every_file():
    assert digests(KEY.tag_message(STATEMENT)) == {
        name: hashlib.sha256(data).hexdigest() for name, data in FILES.items()
    }


def test_a_release_is_refused_without_a_statement_or_with_one_out_of_place():
    not_signed = "the release is not signed by its publisher"
    assert refusal("Strugglebus public release mirror v1\n{}\n") == not_signed
    assert refusal(STATEMENT) == not_signed
    # The statement must start a line of its own.
    assert refusal("x" + KEY.tag_message(STATEMENT)[len("Strugglebus public release mirror v1\n{}\n"):]) == not_signed
    # A signature placed before the statement signs nothing.
    assert refusal(KEY.sign(STATEMENT.encode()) + "\n" + STATEMENT) == not_signed


def test_a_statement_must_be_signed_by_a_release_key():
    bad = "the release's signature is not valid, or is not by a release key"
    assert refusal(OTHER.tag_message(STATEMENT)) == bad
    assert refusal(KEY.tag_message(STATEMENT).replace("version 0.3.0", "version 0.3.1")) == bad
    assert refusal(KEY.tag_message(STATEMENT, flags=0x01)) == bad


def test_a_statement_for_another_version_is_refused():
    assert refusal(KEY.tag_message(STATEMENT), "0.3.1") == "the signed statement is not for release 0.3.1"
    # Windows line ends are not the statement: nothing in it is recognised.
    assert refusal(KEY.tag_message(statement_for("0.3.0", FILES).replace("\n", "\r\n"))) == (
        "the release is not signed by its publisher"
    )
    carriage_return_inside = STATEMENT.replace("  SHA256SUMS", "  SHA256SUMS\r")
    assert refusal(KEY.tag_message(carriage_return_inside)) == "the signed statement is not for release 0.3.0"


@pytest.mark.parametrize("line", [
    "0" * 64 + " requirements.lock",          # one space, not two
    "0" * 63 + "  requirements.lock",         # a short hash
    "G" * 64 + "  requirements.lock",         # not hexadecimal
    "0" * 64 + "  ",                          # no name
    "0" * 64 + "  ../escape",                 # a path, not a plain name
    "0" * 64 + "  SHA256SUMS",                # a name already listed
    "a comment",
])
def test_a_signed_statement_that_is_malformed_is_refused(line: str):
    statement = STATEMENT + line + "\n"
    assert refusal(KEY.tag_message(statement)) == "the signed statement is malformed"


def test_a_signed_statement_must_name_files_and_end_with_a_line_end():
    assert refusal(KEY.tag_message("strugglebus-bus-release 1\nversion 0.3.0\n")) == "the signed statement names no files"
    cut = STATEMENT.rstrip("\n")
    assert refusal(KEY.tag_message(cut)) == "the signed statement is not for release 0.3.0"


def test_a_file_is_checked_against_the_statement_and_none_may_be_missing():
    signed = digests(KEY.tag_message(STATEMENT))

    fetcher.require_signed(signed, "requirements.lock", b"lock\n")
    with pytest.raises(fetcher.Problem, match="requirements.lock is not the file the publisher signed"):
        fetcher.require_signed(signed, "requirements.lock", b"lock\n ")
    with pytest.raises(fetcher.Problem, match="extra.sh is not the file the publisher signed"):
        fetcher.require_signed(signed, "extra.sh", b"")
    fetcher.require_all_present(signed, [*FILES, "another"])
    with pytest.raises(fetcher.Problem, match="the release is missing SHA256SUMS, which its publisher signed"):
        fetcher.require_all_present(signed, ["requirements.lock", "strugglebus-0.3.0-py3-none-any.whl"])


def test_the_cryptography_library_can_stand_in_for_the_python_check():
    """The server paths pass the library's check; both must reach the same answer."""
    def library(public: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True

    good = KEY.sign(STATEMENT.encode())
    assert signer(good, verifies=library) == signer(good) == fetcher.key_fingerprint(KEY.key_blob)
    assert signer(KEY.sign(b"other"), verifies=library) is None
