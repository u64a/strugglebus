"""tools/bootstrap.ps1, verifying the host code before any of it runs (docs/app-host-integration.md 2.2 step 3): the
built-in release keys, the security-key flags, the host's own tree_sha256 rule and the release.toml reader. Each is
checked against the host's Python code or a real signature, in PowerShell 7 and in Windows PowerShell 5.1 (all a
fresh PC has)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from workerhost import signing, update

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "bootstrap.ps1"
PWSH = shutil.which("pwsh")
WINPS = shutil.which("powershell")
KEYGEN = next((k for k in signing.KEYGEN_CANDIDATES[:2] if Path(k).is_file()), None)
SHELLS = [s for s in (PWSH, WINPS) if s]
pytestmark = pytest.mark.skipif(not SHELLS, reason="no PowerShell")
REAL_TOML, REAL_SIG = ROOT / "release.toml", ROOT / "release.toml.sig"
# A real release and its real signature (serial 9, YubiKey A, touch and PIN), kept as test data: the live pair above
# doesn't match while a release PR waits for its signature, and that must not turn every release PR red.
SIGNED = ROOT / "tests" / "data" / "signed-release"
SIGNED_TOML, SIGNED_SIG = SIGNED / "release.toml", SIGNED / "release.toml.sig"


def clean_env(shell: str) -> dict:
    """Windows PowerShell 5.1 started from a PowerShell 7 session inherits 7's PSModulePath and then can't load its
    own modules (Get-Acl, Get-AuthenticodeSignature). A fresh PC starts 5.1 directly, so the tests drop it."""
    env = dict(os.environ)
    if shell == WINPS:
        env.pop("PSModulePath", None)
    return env


def run(body: str, shell: str):
    driver = f"$ErrorActionPreference = 'Stop'\n. '{SCRIPT}'\n{body}"
    r = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", driver], capture_output=True, text=True,
                       timeout=120, stdin=subprocess.DEVNULL, env=clean_env(shell))
    assert r.returncode == 0, r.stderr + r.stdout
    return json.loads(r.stdout)


def test_the_release_keys_are_the_three_that_sign_bootstrap_pins():
    """The same YubiKeys everywhere: bootstrap.ps1's built-in keys have exactly sign-bootstrap.ps1's fingerprints."""
    text = SCRIPT.read_text(encoding="ascii")
    blobs = re.findall(r"'sk-ssh-ed25519@openssh\.com (AAAA[A-Za-z0-9+/=]+)'", text)
    fps = {"SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(b)).digest()).decode().rstrip("=")
           for b in blobs}
    pinned = set(re.findall(r"SHA256:[A-Za-z0-9+/]{43}", (ROOT / "tools" / "sign-bootstrap.ps1").read_text()))
    assert len(blobs) == 3 and fps == pinned


@pytest.mark.parametrize("shell", SHELLS)
def test_the_signers_file_allows_the_release_namespace_only(shell):
    out = run("ConvertTo-Json @(Get-ReleaseSigners)", shell)
    lines = [ln for ln in out[0].split("\n") if ln]
    assert len(lines) == 3 and all(ln.startswith('release namespaces="strugglebus-release" sk-ssh-ed25519') for ln in lines)


@pytest.mark.parametrize("shell", SHELLS)
def test_the_flags_of_the_real_release_signature(shell, tmp_path):
    out = run(f"ConvertTo-Json @(Get-SkFlags ([IO.File]::ReadAllText('{SIGNED_SIG}')))", shell)
    assert out == [5]  # touch and PIN, as the host's own check reads it (workerhost/signing.py)


@pytest.mark.parametrize("shell", SHELLS)
def test_a_malformed_signature_throws(shell):
    out = run("try { Get-SkFlags \"-----BEGIN SSH SIGNATURE-----`nAAAA`n-----END SSH SIGNATURE-----\"; "
              "ConvertTo-Json @('no throw') } catch { ConvertTo-Json @('threw') }", shell)
    assert out == ["threw"]


@pytest.mark.parametrize("shell", SHELLS)
def test_tree_sha256_matches_the_hosts_rule_including_its_ordinal_sort(shell, tmp_path):
    files = {"wh.py": b"print('wh')\n", "README.md": b"# r\n", "config.template.toml": b"x = 1\n",
             "workerhost/Zed.py": b"z\n", "workerhost/abc.py": b"a\r\n", "workerhost/_b.py": b""}
    for p, data in files.items():
        (tmp_path / p).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / p).write_bytes(data)
    body = ("$f = @{}; " + "; ".join(f"$f['{p}'] = [IO.File]::ReadAllBytes('{tmp_path / p}')" for p in files)
            + "; ConvertTo-Json @(Get-TreeSha256 $f)")
    assert run(body, shell) == [update.tree_sha256(files)]


@pytest.mark.parametrize("shell", SHELLS)
def test_the_installed_path_rule_is_the_hosts(shell):
    paths = ["wh.py", "README.md", "config.template.toml", "workerhost/host.py", "workerhost/sub/x.py",
             "workerhost/x.txt", "install.ps1", "tools/make-release.py", "WH.PY", "workerhost/a-b.py"]
    out = run("ConvertTo-Json @(" + ", ".join(f"(Test-InstalledPath '{p}')" for p in paths) + ")", shell)
    assert out == [update.wanted(p) for p in paths]


@pytest.mark.parametrize("shell", SHELLS)
def test_the_real_release_toml_reads(shell):
    if not REAL_TOML.is_file():
        pytest.skip("no release.toml in this layout")
    out = run(f"ConvertTo-Json (Read-ReleaseText ([IO.File]::ReadAllText('{REAL_TOML}'))) -Compress", shell)
    rel = update.parse_release(REAL_TOML.read_bytes())
    assert (out["serial"], out["version"], out["commit"], out["tree_sha256"]) == (
        rel.serial, rel.version, rel.commit, rel.tree_sha256)


@pytest.mark.parametrize("text, why", [
    ('serial = 1\nversion = "1"\ncommit = "' + "a" * 40 + '"\n', "no tree_sha256"),
    ('serial = 1\nserial = 2\nversion = "1"\ncommit = "' + "a" * 40 + '"\ntree_sha256 = "' + "b" * 64 + '"\n', "twice"),
    ('serial = 1\nversion = "1"\ncommit = "ABC"\ntree_sha256 = "' + "b" * 64 + '"\n', "no commit"),
    ('serial = 1\nversion = "1"\n[t]\ncommit = "' + "a" * 40 + '"\ntree_sha256 = "' + "b" * 64 + '"\n', "no commit"),
])
def test_a_bad_release_toml_is_refused(text, why):
    out = run("try { Read-ReleaseText \"" + text.replace('"', '`"').replace("\n", "`n")
              + "\" | Out-Null; ConvertTo-Json @('read') } catch { ConvertTo-Json @($_.Exception.Message) }", SHELLS[0])
    assert why in out[0]


@pytest.mark.skipif(KEYGEN is None, reason="no Windows OpenSSH ssh-keygen")
@pytest.mark.parametrize("shell", SHELLS)
def test_the_real_release_verifies_and_a_changed_byte_does_not(shell, tmp_path):
    changed = tmp_path / "changed.toml"
    changed.write_bytes(SIGNED_TOML.read_bytes().replace(b"serial = ", b"serial =  ", 1))
    body = (f"$w = '{tmp_path}'; $sig = [IO.File]::ReadAllText('{SIGNED_SIG}'); "
            f"$a = Test-ReleaseSignature ([IO.File]::ReadAllBytes('{SIGNED_TOML}')) $sig '{KEYGEN}' $w; "
            f"$b = Test-ReleaseSignature ([IO.File]::ReadAllBytes('{changed}')) $sig '{KEYGEN}' $w; "
            "ConvertTo-Json @(($a -join ':'), ($b -join ':'))")
    assert run(body, shell) == ["True:good", "False:bad-signature"]


def load_make_release():
    import importlib.util

    spec = importlib.util.spec_from_file_location("make_release", ROOT / "tools" / "make-release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("shell", SHELLS)
def test_the_installer_rule_is_the_same_in_both_places(shell):
    mr = load_make_release()
    paths = ["install.ps1", "setup/10-debloat.ps1", "setup/debloat.txt", "setup/sub/x.ps1", "setup/x.py",
             "tools/bootstrap.ps1", "INSTALL.PS1", "wh.py"]
    out = run("ConvertTo-Json @(" + ", ".join(f"(Test-InstallerPath '{p}')" for p in paths) + ")", shell)
    assert out == [bool(mr.INSTALLER_RE.fullmatch(p)) for p in paths]


def test_installer_sha256_covers_install_ps1_and_setup_at_a_commit():
    """Against this repository's HEAD, in either layout (the code at the top, or in worker-host/)."""
    mr = load_make_release()
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, capture_output=True, text=True,
                         check=True).stdout.strip()
    path = "" if Path(top).resolve() == ROOT.resolve() else ROOT.relative_to(Path(top)).as_posix()
    files = mr.installer_files("HEAD", path)
    assert "install.ps1" in files and any(p.startswith("setup/") for p in files)
    assert all(mr.INSTALLER_RE.fullmatch(p) for p in files)
    assert mr.installer_sha256("HEAD", path) == update.tree_sha256(files)
    text = mr.release_text(9, "2026.11.28", "a" * 40, "b" * 64, False, "n", installer="c" * 64)
    assert 'installer_sha256 = "' + "c" * 64 + '"' in text and update.parse_release(text.encode()).serial == 9


@pytest.mark.parametrize("shell", SHELLS)
def test_an_older_release_or_one_without_installer_sha256_is_refused(shell):
    base = {"serial": 9, "version": "x", "commit": "a" * 40, "tree_sha256": "b" * 64}
    cases = [dict(base, installer_sha256="c" * 64), dict(base, serial=8, installer_sha256="c" * 64), base]
    body = "ConvertTo-Json @(" + ", ".join(
        "(Test-ReleaseFloor @{" + "; ".join(f"{k} = '{v}'" for k, v in c.items()) + "})" for c in cases) + ")"
    assert run(body, shell) == [True, False, False]


def test_the_signed_test_release_is_a_real_one():
    """The test data is the real serial 9 (u64a/strugglebus 5ae86d2), byte for byte, and parses as a release."""
    assert hashlib.sha256(SIGNED_TOML.read_bytes()).hexdigest() == \
        "c02a2431331fb8cd8b64a63ccd008c1d8154466c95da14be92e3bdbc089492ce"
    assert hashlib.sha256(SIGNED_SIG.read_bytes()).hexdigest() == \
        "6c17021d84739891da7e55c4d8f34603e502cfa2331212d62e11cc36d4cff839"
    rel = update.parse_release(SIGNED_TOML.read_bytes())
    assert (rel.serial, rel.version) == (9, "2026.11.27.4")


@pytest.mark.parametrize("shell", SHELLS)
def test_the_prerequisites_follow_the_engines(shell):
    out = run("ConvertTo-Json @(((Get-NeededPrereqs @('ghcp')) -join ','), ((Get-NeededPrereqs @('claude', 'ghcp')) -join ','), "
              "((Get-NeededPrereqs @('evil')) -join ','))", shell)
    assert out == ["python,git,pwsh,gh,ghcp", "python,git,pwsh,gh,claude,ghcp", "python,git,pwsh,gh"]


def test_the_release_source_and_ssh_keygen_are_built_in_not_from_the_data_file():
    text = SCRIPT.read_text(encoding="ascii")
    assert "$ReleaseRepo = 'https://github.com/u64a/strugglebus'" in text and "$ReleaseFolder = 'worker-host'" in text
    assert "System32\\OpenSSH\\ssh-keygen.exe" in text and "$SB.release" not in text


@pytest.mark.skipif(KEYGEN is None or shutil.which("git") is None, reason="needs git and Windows OpenSSH")
def test_the_whole_fetch_against_this_repositorys_signed_release(tmp_path):
    """Get-VerifiedRelease against a clone of this repository's own main: the real signed release is verified and
    exactly its host and installer files are staged. A release without installer_sha256 is refused before anything
    is staged instead. (The VM test runs the same against github.com.)"""
    top = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip())
    folder = ROOT.relative_to(top).as_posix() if top.resolve() != ROOT.resolve() else ""
    if not folder:
        pytest.skip("needs the monorepo layout")
    if subprocess.run(["git", "rev-parse", "--verify", "--quiet", "main"], cwd=top, capture_output=True).returncode:
        pytest.skip("no local main branch to clone (a CI checkout)")
    main_toml = subprocess.run(["git", "show", f"main:{folder}/release.toml"], cwd=top, capture_output=True).stdout
    git = shutil.which("git")
    body = (f"function Say([string]$t) {{ }}; $Keygen = '{KEYGEN}'; $GitTestAllow = @('-c', 'protocol.file.allow=always'); "
            f"try {{ $r = Get-VerifiedRelease '{git}' '{tmp_path}' '{top.as_posix()}' '{folder}'; "
            "ConvertTo-Json @(\"serial $($r.release.serial)\") } catch { ConvertTo-Json @($_.Exception.Message) }")
    out = run(body, PWSH or SHELLS[0])
    if b"installer_sha256" not in main_toml:
        assert "no installer_sha256" in out[0] and not (tmp_path / "stage").exists()
        return
    rel = update.parse_release(main_toml)
    assert out == [f"serial {rel.serial}"], out
    staged = sorted(p.relative_to(tmp_path / "stage").as_posix() for p in (tmp_path / "stage").rglob("*") if p.is_file())
    assert "wh.py" in staged and "install.ps1" in staged and any(p.startswith("setup/") for p in staged)
    assert all(update.wanted(p) or load_make_release().INSTALLER_RE.fullmatch(p) for p in staged)


def test_what_the_elevated_scripts_load_is_all_covered_by_the_signed_hashes():
    """install.ps1 and setup\\*.ps1 run as administrator from the bootstrap. Every file they load from their own
    folder must be covered by tree_sha256 or installer_sha256 (u64-security, #humans 28905), so a new helper can't
    run unhashed. Two named exceptions: keys\\allowed_signers (only with -PinSigners, never used by the bootstrap,
    which pins its own) and the .git existence check."""
    mr = load_make_release()
    allowed_exceptions = {"keys/allowed_signers", ".git"}
    for script in [ROOT / "install.ps1", *sorted((ROOT / "setup").glob("*.ps1"))]:
        text = script.read_text(encoding="utf-8")
        assert not re.search(r"Import-Module|\.psm1|\.psd1|^\s*\.\s+\S", text, re.M), script.name
        for ref in re.findall(r"Join-Path \$(?:Source|PSScriptRoot)\s+'([^']+)'", text, re.I):
            rel = ref.replace("\\", "/")
            base = "setup/" if script.parent.name == "setup" else ""
            path = base + rel
            if path in allowed_exceptions:
                continue
            if path.endswith("/*.py"):
                assert path == "workerhost/*.py", path  # every one of them is in tree_sha256
                continue
            assert update.wanted(path) or mr.INSTALLER_RE.fullmatch(path), f"{script.name} loads {path}, not hashed"


def test_setup_holds_only_files_the_installer_hash_covers():
    mr = load_make_release()
    extra = [p.name for p in (ROOT / "setup").iterdir() if not mr.INSTALLER_RE.fullmatch(f"setup/{p.name}")]
    assert extra == []  # the bootstrap refuses a release whose setup\ holds anything else


@pytest.mark.parametrize("shell", SHELLS)
def test_microsoft_is_read_from_the_organisation_field_only(shell):
    names = ["CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
             "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
             "CN=Evil, O=Microsoft Corporation Ltd, C=US", "CN=O=Microsoft Corporation, O=Evil", "O=microsoft corporation"]
    out = run("ConvertTo-Json @(" + ", ".join(f"(Test-MicrosoftName '{n}')" for n in names) + ")", shell)
    assert out == [True, True, False, False, False]


def test_the_powershell_pin_is_the_agreed_one():
    """Three independent sources agreed on this file (#humans 28927-28929): change it only with a new agreement."""
    text = SCRIPT.read_text(encoding="ascii")
    assert "version = '7.6.10'; line = 'LTS'; file = 'PowerShell-7.6.10-win-x64.zip'; size = 109626781" in text
    assert "sha256 = '7D871531806EB1646264E4BBABD9F0C30C23355591BC756BB9909448C29AE166'" in text
    assert "url = 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.10/PowerShell-7.6.10-win-x64.zip'" in text
    assert "Microsoft.PowerShell" not in text  # never the MSIX


@pytest.mark.parametrize("shell", SHELLS)
def test_user_writable_folders_are_spotted(shell, tmp_path):
    mine = tmp_path / "mine"
    mine.mkdir()
    out = run(f"ConvertTo-Json @((Test-UserWritable '{tmp_path / 'missing'}'), (Test-UserWritable 'C:\\Windows\\System32'))",
              shell)
    assert out == [True, False]  # a missing folder counts as writable; System32 is not


def test_the_bootstrap_parses():
    """A parse error stops the whole script loading (a "$Name:" in a string is the usual one)."""
    r = subprocess.run([SHELLS[0], "-NoProfile", "-NonInteractive", "-Command",
                        f"$t = $null; $e = $null; [void][Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', "
                        "[ref]$t, [ref]$e); $e.Count"], capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == "0", r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_a_hostile_user_gitconfig_cannot_steer_the_elevated_git(tmp_path):
    """The operator's ~/.gitconfig is writable by any unelevated program of theirs: an `insteadOf` to `ext::` would run
    a command as administrator at the clone (u64-security, #humans 28966). The bootstrap's git reads no user or
    system config and allows only https (here, plus the test's own file transport)."""
    origin = tmp_path / "origin"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    hostile_home = tmp_path / "hostile-home"
    hostile_home.mkdir()
    marker = tmp_path / "PWNED.txt"
    (hostile_home / ".gitconfig").write_text(
        f'[url "ext::cmd.exe /c echo pwned > {marker.as_posix()}"]\n\tinsteadOf = {origin.as_posix()}\n'
        '[protocol "ext"]\n\tallow = always\n[core]\n\tsshCommand = cmd.exe /c echo pwned\n', encoding="ascii")
    work = tmp_path / "work"
    work.mkdir()
    env = dict(os.environ, HOME=str(hostile_home), USERPROFILE=str(hostile_home), XDG_CONFIG_HOME=str(hostile_home))
    git = shutil.which("git")
    driver = (f"$ErrorActionPreference = 'Stop'\n. '{SCRIPT}'\n$GitTestAllow = @('-c', 'protocol.file.allow=always')\n"
              f"try {{ Invoke-GitBytes '{git}' @('clone', '--quiet', '--bare', '{origin.as_posix()}', '{(work / 'm').as_posix()}') "
              f"'{work}' | Out-Null; 'cloned' }} catch {{ \"failed: $($_.Exception.Message)\" }}\n"
              f"$c = Invoke-GitBytes '{git}' @('config', '--show-origin', '--list') '{work}'; [Text.Encoding]::UTF8.GetString($c)")
    r = subprocess.run([PWSH or SHELLS[0], "-NoProfile", "-NonInteractive", "-Command", driver], capture_output=True,
                       text=True, timeout=120, env=env)
    assert not marker.exists(), "the hostile config ran a command"
    assert "cloned" in r.stdout, r.stdout + r.stderr
    assert "hostile-home" not in r.stdout and "insteadof" not in r.stdout.lower()  # the user's config wasn't read at all


def test_winget_is_never_called_through_path():
    text = SCRIPT.read_text(encoding="ascii")
    assert "& winget" not in text and "& (Get-Winget)" in text
    assert "Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller'" in text


def test_the_usage_example_skips_the_operators_profile():
    text = SCRIPT.read_text(encoding="ascii")
    assert "powershell -NoProfile -ExecutionPolicy Bypass -File .\\bootstrap.ps1" in text
    assert "powershell -ExecutionPolicy Bypass -File" not in text


@pytest.mark.parametrize("shell", SHELLS)
def test_the_account_password_is_long_random_and_varied(shell):
    body = ("$a = @(1..3 | ForEach-Object { $s = New-RandomPassword; "
            "$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); "
            "try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) } }); "
            "ConvertTo-Json @($a)")
    pws = run(body, shell)
    assert len(set(pws)) == 3 and all(len(p) == 32 for p in pws)
    for p in pws:
        assert re.search("[A-Z]", p) and re.search("[a-z]", p) and re.search("[0-9]", p) and re.search(r"[^A-Za-z0-9]", p)
        assert not re.search(r"[\s\"'`$]", p)  # nothing a shell or a quote could break


@pytest.mark.parametrize("shell", SHELLS)
def test_the_pinned_list_is_the_sites_keys_plus_the_release_keys(shell):
    site = ['coord namespaces="strugglebus-fleet" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA test']
    out = run(f"ConvertTo-Json @(Get-PinnedSignersText @('{site[0]}'))", shell)
    lines = [ln for ln in out[0].split("\n") if ln]
    assert lines[0] == site[0] and len(lines) == 4
    assert all(ln.startswith('release namespaces="strugglebus-release" sk-ssh-ed25519@openssh.com ') for ln in lines[1:])


@pytest.mark.parametrize("shell", SHELLS)
def test_the_generated_site_file_is_one_the_host_accepts(shell, tmp_path):
    body = ("ConvertTo-Json @(Get-SiteText @{ bus_url = 'https://bus.example.lan'; fleet_source = 'bus'; "
            "remotes = @('https://github.com/acme/', 'https://forgejo.example.lan/') })")
    text = run(body, shell)[0]
    site = tmp_path / "site.toml"
    site.write_text(text, encoding="ascii")
    r = subprocess.run([sys.executable, "-I", str(ROOT / "workerhost" / "sitefile.py"), str(site)], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "bus.example.lan" in r.stdout and "acme" in r.stdout


def test_steps_4_to_6_keep_the_password_out_of_arguments_and_transcripts():
    """u64-security, #humans 28966: the password goes to install.ps1 on stdin only; no transcript, no plain-text
    conversion beyond that one write."""
    text = SCRIPT.read_text(encoding="ascii")
    assert "Start-Transcript" not in text and "ConvertFrom-SecureString" not in text
    assert "'-PasswordStdin'" in text and "-Password $" not in text.split("function Invoke-Install")[1].split("if ($MyInvocation")[0]
    assert text.count("PtrToStringBSTR") == 1  # the stdin write, nowhere else


INF = ("[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\nSeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551\r\n"
       "SeDenyNetworkLogonRight = *S-1-5-32-546\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n")


@pytest.mark.parametrize("shell", SHELLS)
def test_the_four_logon_denials_are_added_once_and_nothing_else_changes(shell, tmp_path):
    f = tmp_path / "rights.inf"
    f.write_text(INF, encoding="ascii", newline="")
    sid = "S-1-5-21-1-2-3-1001"
    body = (f"$t = [IO.File]::ReadAllText('{f}'); $a = Update-UserRightsInf $t '{sid}' $DeniedRights; "
            f"$b = Update-UserRightsInf $a '{sid}' $DeniedRights; ConvertTo-Json @($a, ($a -ceq $b))")
    out, same = run(body, shell)
    lines = out.split("\r\n")
    assert same is True  # running it again changes nothing
    assert "SeDenyNetworkLogonRight = *S-1-5-32-546,*" + sid in lines  # an existing holder kept, ours added
    for right in ("SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeDenyServiceLogonRight"):
        assert f"{right} = *{sid}" in lines
    assert "SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551" in lines  # the batch right untouched
    assert lines.index("[Version]") > max(i for i, ln in enumerate(lines) if ln.startswith("SeDeny"))  # inside the section


def test_the_one_time_code_never_reaches_a_command_line():
    text = SCRIPT.read_text(encoding="ascii")
    enrol = text.split("function Invoke-Enrol")[1].split("function Start-Host")[0]
    assert "'--code-stdin'" in enrol and "$data.enrol_code)" not in enrol.split("Invoke-AsAccount")[1].split(")")[0]
    assert "Clear-EnrolCode $data" in enrol  # blanked in the file straight after


ISOLATION_SHA256 = "c3cbc4de552f10a160bd460ee7e5903ba22d161d641d664093a7c9df95cc4995"  # u64-security 5ee2b05, 29003


def test_the_vendored_isolation_check_is_u64_securitys_reviewed_version():
    """It's dot-sourced ELEVATED by the bootstrap, so an update is a security change: u64-security posts the new hash
    and reviews it, and this pin changes with it (#humans 29003)."""
    script = ROOT / "setup" / "Get-WorkerIsolationHits.ps1"
    if not script.is_file():
        pytest.skip("not vendored in this checkout yet (u64a/strugglebus PR 59)")
    # The COMMITTED bytes (LF), as the bootstrap reads them; a Windows checkout writes .ps1 with CRLF
    # (.gitattributes), so the working file is compared with its line endings undone.
    blob = subprocess.run(["git", "cat-file", "blob", "HEAD:./setup/Get-WorkerIsolationHits.ps1"], cwd=ROOT,
                          capture_output=True)
    raw = blob.stdout if blob.returncode == 0 else script.read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(raw).hexdigest() == ISOLATION_SHA256 and b"\r" not in raw


def test_step_11_shows_paths_at_the_console_only_and_gives_the_host_counts():
    text = SCRIPT.read_text(encoding="ascii")
    step = text.split("function Invoke-IsolationCheck")[1].split("function Remove-DataFileOffer")[0]
    assert "setup\\Get-WorkerIsolationHits.ps1" in step and "-Account $account -Exclude" in step
    record = step.split("$record = ")[1].split("}")[0]
    assert "exec_hits = $exec.Count" in record and "info_hits = $info.Count" in record
    assert "$h" not in record and ".Path" not in record and ".Source" not in record  # counts only, never a path


def test_still_ascii_and_lf_only():
    raw = SCRIPT.read_bytes()
    assert max(raw) < 128 and b"\r" not in raw
