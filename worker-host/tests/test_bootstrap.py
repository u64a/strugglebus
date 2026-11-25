"""tools/bootstrap.ps1, the App's install script (docs/app-host-integration.md section 2). Code and data are separate
(security review): the bootstrap is a fixed release file, and the App's output is a data file that is
never executed. Tested here: the data file's canonical form (the vector the App's generator matches), the value
checks, the digest (M2), the signer fingerprints and blanking the one-time code (Q1). The install steps are not built
yet."""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import vectors
from workerhost import signing

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "bootstrap.ps1"
VECTOR = vectors.path("host-enrol", "sbhost-enrol.json")
PWSH = shutil.which("pwsh")
WINPS = shutil.which("powershell")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 (pwsh) is not installed")

GOOD = json.loads(VECTOR.read_bytes())
KEYS = ["v", "written_at", "device", "bus_url", "bus_ca_pem", "host_prefix", "enrol_code", "engines", "dedicated",
        "signers", "fleet_source", "remotes"]


def canonical(data: dict) -> bytes:
    """The reference renderer, independent of the PowerShell one."""
    return (json.dumps({k: data[k] for k in KEYS}, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def run(body: str, shell: str | None = None):
    driver = f". '{SCRIPT}'\n{body}"
    r = subprocess.run([shell or PWSH, "-NoProfile", "-NonInteractive", "-Command", driver], capture_output=True,
                       text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def read(raw: bytes, tmp_path: Path, single: bool = False, shell: str | None = None) -> dict:
    """Read-SbData over these bytes: {"ok": data} or {"error": message}."""
    f = tmp_path / "data.json"
    f.write_bytes(raw)
    flag = " -SingleSigner" if single else ""
    return run(f"try {{ $d = Read-SbData ([IO.File]::ReadAllBytes('{f}')){flag}; ConvertTo-Json @{{ ok = $d }} -Depth 5 "
               f"-Compress }} catch {{ ConvertTo-Json @{{ error = $_.Exception.Message }} -Compress }}", shell)


def with_(**over) -> bytes:
    return canonical({**GOOD, **over})


def test_the_vector_is_canonical_and_reads_back_whole(tmp_path):
    raw = VECTOR.read_bytes()
    assert raw == canonical(GOOD)  # the committed bytes are what json.dumps gives
    assert b"\r" not in raw and raw.endswith(b"}\n") and raw.count(b"\n") == 1
    got = read(raw, tmp_path)
    assert got == {"ok": GOOD}


def test_the_powershell_renderer_gives_the_vector_bytes(tmp_path):
    f = tmp_path / "out.txt"
    run(f"$d = ConvertFrom-SbJson ([IO.File]::ReadAllText('{VECTOR}')); [IO.File]::WriteAllText('{f}', "
        f"(Format-SbData $d)); ConvertTo-Json 1")
    assert f.read_bytes() == VECTOR.read_bytes()


@pytest.mark.parametrize("raw, why", [
    (VECTOR.read_bytes().replace(b"\n", b"\r\n"), "canonical"),                         # CRLF
    (b"\xef\xbb\xbf" + VECTOR.read_bytes(), "ASCII"),                                    # a BOM
    (VECTOR.read_bytes().replace(b'"v":1,', b'"v":1, '), "canonical"),                   # spacing
    (VECTOR.read_bytes().replace(b'"v":1,', b'"v":1,"v":1,'), ""),                        # a repeated key
    (VECTOR.read_bytes().replace(b'"device":', b'"zzz":1,"device":'), "unknown key zzz"),
    (VECTOR.read_bytes().replace(b"office", b"\\u006ffice", 1), "canonical"),            # an escape
    (json.dumps(GOOD, indent=2).encode() + b"\n", "canonical"),                          # pretty-printed
    (b"$(Start-Process calc)", "not JSON"),
])
def test_anything_but_the_canonical_form_is_refused(raw, why, tmp_path):
    got = read(raw, tmp_path)
    assert "error" in got and why in got["error"]


@pytest.mark.parametrize("over, field", [
    ({"v": 2}, "v"),
    ({"written_at": "2026-11-24 04:02"}, "written_at"),
    ({"device": "Office Laptop"}, "device"),
    ({"bus_url": "http://bus.example.lan"}, "bus_url"),
    ({"bus_url": "https://bus.example.lan/'; Remove-Item C:\\ -Recurse #"}, "bus_url"),
    ({"host_prefix": "host--office"}, "host_prefix"),
    ({"host_prefix": "host-office-"}, "host_prefix"),
    ({"host_prefix": "Host"}, "host_prefix"),
    ({"enrol_code": "sbhe1_short"}, "enrol_code"),
    ({"bus_ca_pem": "bm90IGEgY2VydA=="}, "bus_ca_pem"),       # base64 of "not a cert"
    ({"bus_ca_pem": "not base64!"}, "bus_ca_pem"),
    ({"engines": []}, "engines"),
    ({"engines": ["ghcp", "ghcp"]}, "engines"),
    ({"engines": ["cursor"]}, "engines"),
    ({"dedicated": "yes"}, "dedicated"),
    ({"fleet_source": "anywhere"}, "fleet_source"),
    ({"remotes": ["https://github.com/a/b/"]}, "remotes"),
    ({"signers": [s.replace("strugglebus-fleet", "strugglebus-release") for s in GOOD["signers"]]}, "signers"),
    ({"signers": GOOD["signers"][:1]}, "signers: at least two"),
])
def test_each_bad_value_is_named(over, field, tmp_path):
    got = read(with_(**over), tmp_path)
    assert "error" in got and field in got["error"]


def test_one_signer_only_with_the_testing_switch_and_a_blank_code_is_fine(tmp_path):
    assert "ok" in read(with_(signers=GOOD["signers"][:1]), tmp_path, single=True)
    assert "ok" in read(with_(enrol_code=""), tmp_path)  # blanked after redeeming


def test_the_digest_and_fingerprints_match_what_the_app_computes(tmp_path):
    raw = VECTOR.read_bytes()
    got = run(f"ConvertTo-Json @{{ d = (Get-FileDigest ([IO.File]::ReadAllBytes('{VECTOR}'))); "
              f"fp = (Get-SignerFingerprint '{GOOD['signers'][0]}') }} -Compress")
    hexd = hashlib.sha256(raw).hexdigest()[:16]
    assert got["d"] == " ".join(hexd[i:i + 4] for i in range(0, 16, 4))
    kind, blob = GOOD["signers"][0].split()[2:4]
    assert got["fp"] == signing.fingerprint(kind, blob)


def test_the_code_is_blanked_and_nothing_else_changes(tmp_path):
    f = tmp_path / "out.txt"
    run(f"$d = ConvertFrom-SbJson ([IO.File]::ReadAllText('{VECTOR}')); [IO.File]::WriteAllText('{f}', "
        f"(Clear-EnrolCode $d)); ConvertTo-Json 1")
    assert f.read_bytes() == with_(enrol_code="")


@pytest.mark.skipif(WINPS is None, reason="Windows PowerShell 5.1 is not installed")
def test_the_checks_run_in_windows_powershell_51(tmp_path):
    """A fresh Windows 11 PC has only Windows PowerShell 5.1: the vector must read the same there, and a bad file
    must still be refused."""
    assert max(SCRIPT.read_bytes()) < 128  # ASCII only: 5.1 reads a file without a BOM as the ANSI code page
    assert read(VECTOR.read_bytes(), tmp_path, shell=WINPS) == {"ok": GOOD}
    assert "error" in read(VECTOR.read_bytes().replace(b"\n", b"\r\n"), tmp_path, shell=WINPS)


def test_the_bootstrap_has_no_data_in_it():
    """The App never edits the bootstrap: it is one fixed release file, checked by hash or signature."""
    text = SCRIPT.read_text(encoding="ascii")
    assert "$SB = @{" not in text and "-DataFile" in text and b"\r" not in SCRIPT.read_bytes()
