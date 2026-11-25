"""site.toml: one site's values (its bus, fleet repository, coordinator, allowed remotes, OpenBao), checked and turned
into the text install.ps1 puts in place of config.template.toml's site placeholders.

    python -I workerhost\\sitefile.py <site.toml>    # prints {"@BUS_URL@": "\\"https://...\\"", ...} as JSON, or exits 2

Every value is checked here and written as a TOML literal (a JSON string is a valid TOML basic string), so nothing in
the file can add a key or a table to config.toml. Standard library only: install.ps1 runs it from the source folder
before anything is installed. site.example.toml is the commented example.
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

HTTPS_HOST = re.compile(r"https://[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?/?")
OWNER_REPO = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")
AGENT = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
PREFIX = re.compile(r"https://[a-z0-9][a-z0-9.-]{0,252}/([A-Za-z0-9_.-]{1,100}/)?")  # whole host, or one owner
SHORT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
DOMAIN = re.compile(r"[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+")
FLEET_SOURCE = re.compile(r"git|bus|either")
TOP = {"bus_url", "fleet_repo", "fleet_source", "vault_repo", "coordinator", "remotes", "repos", "openbao"}
OPENBAO = {"url", "ca_url", "san_domain", "leaf_authority"}


class SiteError(ValueError):
    pass


def _str(data: dict, key: str, pattern: re.Pattern | None, required: bool = False, where: str = "") -> str:
    value = data.get(key, "")
    if not isinstance(value, str) or (value and pattern is not None and not pattern.fullmatch(value)):
        raise SiteError(f"{where}{key}: not a valid value")
    if required and not value:
        raise SiteError(f"{where}{key}: required")
    return value


def check(data: dict) -> dict:
    """The site's values, checked; SiteError names the first that is wrong."""
    unknown = set(data) - TOP
    if unknown:
        raise SiteError(f"unknown key: {sorted(unknown)[0]}")
    out = {"bus_url": _str(data, "bus_url", HTTPS_HOST, required=True),
           "fleet_repo": _str(data, "fleet_repo", OWNER_REPO),
           "fleet_source": _str(data, "fleet_source", FLEET_SOURCE) or "git",
           "vault_repo": _str(data, "vault_repo", OWNER_REPO),
           "coordinator": _str(data, "coordinator", AGENT)}
    remotes = data.get("remotes")
    if not isinstance(remotes, list) or not remotes or not all(isinstance(r, str) and PREFIX.fullmatch(r)
                                                                 for r in remotes):
        raise SiteError("remotes: a list of https://<host>/ or https://<host>/<owner>/ prefixes, at least one")
    out["remotes"] = list(dict.fromkeys(remotes))
    repos = data.get("repos", {})
    if not isinstance(repos, dict) or not all(isinstance(k, str) and SHORT.fullmatch(k) and isinstance(v, str)
                                              and OWNER_REPO.fullmatch(v) for k, v in repos.items()):
        raise SiteError('repos: short-name = "owner/repo" entries')
    out["repos"] = dict(repos)
    ob = data.get("openbao", {})
    if not isinstance(ob, dict) or set(ob) - OPENBAO:
        raise SiteError(f"openbao: only {', '.join(sorted(OPENBAO))}")
    out["openbao"] = {"url": _str(ob, "url", HTTPS_HOST, where="openbao."),
                      "ca_url": _str(ob, "ca_url", HTTPS_HOST, where="openbao."),
                      "san_domain": _str(ob, "san_domain", DOMAIN, where="openbao."),
                      "leaf_authority": _str(ob, "leaf_authority", AGENT, where="openbao.")}
    return out


def placeholders(site: dict) -> dict[str, str]:
    """config.template.toml's site placeholders -> TOML text (a quoted string, an array, or table lines)."""
    q = json.dumps
    remotes = "[\n" + "".join(f"  {q(r)},\n" for r in site["remotes"]) + "]"
    repos = "".join(f"{q(k)} = {q(v)}\n" for k, v in site["repos"].items())  # quoted: a bare a.b would be a table
    ob = site["openbao"]
    return {"@BUS_URL@": q(site["bus_url"]), "@FLEET_REPO@": q(site["fleet_repo"]), "@FLEET_SOURCE@": q(site["fleet_source"]),
            "@VAULT_REPO@": q(site["vault_repo"]), "@COORDINATOR@": q(site["coordinator"]),
            "@REMOTES@": remotes, "@REPOS@": repos, "@OPENBAO_URL@": q(ob["url"]),
            "@OPENBAO_CA_URL@": q(ob["ca_url"]), "@SAN_DOMAIN@": q(ob["san_domain"]),
            "@LEAF_AUTHORITY@": q(ob["leaf_authority"])}


def load(path: Path) -> dict[str, str]:
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise SiteError(f"cannot read {path}: {e}") from None
    return placeholders(check(data))


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: sitefile.py <site.toml>")
        return 2
    try:
        print(json.dumps(load(Path(argv[0]))))
    except SiteError as e:
        print(f"site file: {e}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
