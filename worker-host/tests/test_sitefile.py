"""site.toml -> config.toml (workerhost/sitefile.py, install.ps1 -SiteFile): every value checked, written as a TOML
literal, so a site file can set its own values and nothing else; and the code itself carries no site's values."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from workerhost import config, sitefile, urls

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "site.example.toml"
TEMPLATE = ROOT / "config.template.toml"
GOOD = {"bus_url": "https://bus.example.lan", "fleet_repo": "acme/fleet",
        "remotes": ["https://github.com/acme/", "https://git.example.lan/"]}


def render(site: dict, tmp_path: Path) -> str:
    """The template with machine values and this site's, as install.ps1 writes a new config."""
    text = TEMPLATE.read_text(encoding="utf-8")
    machine = {"@HOST_NAME@": "box1", "@AGENT_PREFIX@": "sb-host-box1", "@WORKERS_ROOT@": str(tmp_path / "w"),
               "@BUS_CA@": "C:\\ca.crt", "@COPILOT_EXE@": "C:\\copilot.exe", "@GH_EXE@": "gh", "@GIT_EXE@": "git",
               "@PYTHON_EXE@": "C:\\py\\python.exe", "@MAX_WORKERS@": "6", "@WORKER_COMMIT_GB@": "8",
               "@DEFAULT_ENGINE@": "ghcp"}
    for k, v in {**machine, **sitefile.placeholders(sitefile.check(site))}.items():
        text = text.replace(k, v)
    return text


def test_a_minimal_site_makes_a_config_that_loads(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = render(GOOD, tmp_path)
    assert re.findall(r"@[A-Z_]+@", text) == []
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    cfg = config.load(tmp_path / "config.toml")
    assert cfg.bus_url == "https://bus.example.lan" and cfg.fleet_remote() == "https://github.com/acme/fleet.git"
    assert cfg.remotes == GOOD["remotes"] and cfg.repos == {} and cfg.vault_remote() == ""
    assert cfg.coordinator_name == "" and cfg.openbao.url == "" and cfg.openbao.leaf_authority == ""


def test_fleet_source_defaults_to_git_and_takes_only_the_three_values():
    base = {"bus_url": "https://bus.example.lan", "remotes": ["https://github.com/acme/"]}
    assert sitefile.check(base)["fleet_source"] == "git"
    assert sitefile.check({**base, "fleet_source": "either"})["fleet_source"] == "either"
    with pytest.raises(sitefile.SiteError, match="fleet_source"):
        sitefile.check({**base, "fleet_source": "gitx"})


def test_the_example_is_a_valid_site_file():
    assert set(sitefile.load(EXAMPLE)) == {"@BUS_URL@", "@FLEET_REPO@", "@FLEET_SOURCE@", "@VAULT_REPO@", "@COORDINATOR@",
                                           "@REMOTES@", "@REPOS@", "@OPENBAO_URL@", "@OPENBAO_CA_URL@",
                                           "@SAN_DOMAIN@", "@LEAF_AUTHORITY@"}


def test_every_site_placeholder_in_the_template_comes_from_the_site_file():
    machine = {"@HOST_NAME@", "@AGENT_PREFIX@", "@WORKERS_ROOT@", "@BUS_CA@", "@COPILOT_EXE@", "@GH_EXE@",
               "@GIT_EXE@", "@PYTHON_EXE@", "@MAX_WORKERS@", "@WORKER_COMMIT_GB@", "@DEFAULT_ENGINE@"}
    in_template = set(re.findall(r"@[A-Z_]+@", TEMPLATE.read_text(encoding="utf-8")))
    assert in_template == machine | set(sitefile.load(EXAMPLE))


@pytest.mark.parametrize("bad, where", [
    ({"bus_url": "http://bus.lan"}, "bus_url"),
    ({"bus_url": ""}, "bus_url"),
    ({"fleet_repo": "acme"}, "fleet_repo"),
    ({"remotes": []}, "remotes"),
    ({"remotes": ["https://github.com/acme"]}, "remotes"),  # a prefix ends with /
    ({"remotes": ["https://github.com/a/b/"]}, "remotes"),  # host or one owner only
    ({"coordinator": "Coord One"}, "coordinator"),
    ({"repos": {"x": "not a repo"}}, "repos"),
    ({"openbao": {"url": "https://v.lan", "token": "x"}}, "openbao"),
    ({"openbao": {"san_domain": "lan"}}, "san_domain"),
    ({"surprise": 1}, "unknown key"),
])
def test_a_bad_value_is_named_and_nothing_is_written(bad, where):
    with pytest.raises(sitefile.SiteError, match=where):
        sitefile.check({**GOOD, **bad})


def test_values_are_literals_that_cannot_add_keys_or_tables(tmp_path, monkeypatch):
    # Every value passes a strict pattern first; even so, what is written is a TOML string, never raw text.
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    for evil in ('acme/x"\nsurprise = 1', "acme/x\n[runtime]"):
        with pytest.raises(sitefile.SiteError):
            sitefile.check({**GOOD, "fleet_repo": evil})
    p = sitefile.placeholders(sitefile.check({**GOOD, "repos": {"a.b-c": "acme/a.b-c"}}))
    assert tomllib.loads(f"x = {p['@BUS_URL@']}\nr = {p['@REMOTES@']}\n[repos]\n{p['@REPOS@']}") == {
        "x": "https://bus.example.lan", "r": GOOD["remotes"], "repos": {"a.b-c": "acme/a.b-c"}}


def test_the_command_line_install_ps1_runs(tmp_path):
    site = tmp_path / "site.toml"
    site.write_text('bus_url = "https://bus.example.lan"\nremotes = ["https://github.com/acme/"]\n', encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(ROOT / "workerhost" / "sitefile.py"), str(site)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and json.loads(r.stdout)["@BUS_URL@"] == '"https://bus.example.lan"'
    site.write_text('bus_url = "http://insecure"\n', encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(ROOT / "workerhost" / "sitefile.py"), str(site)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and r.stdout.startswith("site file: bus_url")


def test_the_code_carries_no_sites_values():
    # The defaults are empty or generic: a site's own values come from its site file (sites/ is the private
    # deployment's, and does not ship).
    cfg = config.Config(host_name="x")
    assert (cfg.bus_url, cfg.vault_repo, cfg.fleet_repo, cfg.coordinator_name) == ("", "", "", "")
    assert (cfg.openbao.url, cfg.openbao.ca_url, cfg.openbao.leaf_authority, cfg.openbao.san_domain) == ("",) * 4
    assert urls.DEFAULT_REMOTES == ("https://github.com/",)
    words = site_words()
    assert {"bus.example.lan", "acme", "coord-main"} <= words  # the test site's, at least (and any deployment's)
    for path in (ROOT / "workerhost").glob("*.py"):  # string values in the code; docstrings and comments aside
        for value in string_values(path):
            assert not any(w in value for w in words), f"{path.name}: {value[:60]}"
    code = "\n".join(l for l in TEMPLATE.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#"))
    assert not any(w in code for w in words), "config.template.toml"  # placeholders only


def site_words() -> set[str]:
    """Each site file's own names: its hosts, GitHub owners and coordinator (the test site's here; a deployment's
    sites/*.toml too, where they exist). The example's placeholders are not site values."""
    words = set()
    for f in [ROOT / "tests" / "data" / "site.toml", *(ROOT / "sites").glob("*.toml")]:
        s = sitefile.check(tomllib.loads(f.read_text(encoding="utf-8")))
        urls_ = [s["bus_url"], *s["remotes"], s["openbao"]["url"], s["openbao"]["ca_url"]]
        words |= {u.split("/")[2].split(":")[0] for u in urls_ if u}
        words |= {u.split("/")[3] for u in s["remotes"] if u.count("/") > 3}
        words |= {r.split("/")[0] for r in (s["fleet_repo"], s["vault_repo"]) if r}
        words |= {s["coordinator"]} - {""}
    return words - {"github.com"}


def string_values(path: Path) -> list[str]:
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    docs = {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and n.body
            and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]
