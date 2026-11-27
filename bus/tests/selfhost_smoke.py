"""Installs, updates and rolls back a self-hosted bus for real, in containers.

Run it before a release; it is not part of the pytest suite:

    uv run python tests/selfhost_smoke.py            # both install types
    uv run python tests/selfhost_smoke.py debian     # or: docker

It needs Docker with privileged containers and internet access (Debian
mirrors, pypi.org, Docker Hub), and takes about ten minutes. It builds three
wheels from a copy of this source tree - the current version, a pretend newer
one, and a newer one that cannot start - and checks that:

- the Debian installer produces a healthy bus behind its gateway;
- the gateway refuses a visitor from a public address;
- the daily update does nothing while switched off, installs the newer
  release while on, and puts the previous version back when a release cannot
  start, without retrying it;
- the Docker install becomes healthy, and `update.sh` does the same.

An installed bus takes a release only if the project owner's hardware key signed
it, and no test can use that key. So the three wheels built here trust a key made
for this run instead, and each pretend release is signed with it. The updaters
then run their whole signature check for real. Nothing built here is a release.

Nothing outside the containers and a temporary folder is changed.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from release_signing import ReleaseKey, statement_for

REPOSITORY = Path(__file__).resolve().parents[1]
# The key the wheels built for this run trust in place of the owner's.
SMOKE_KEY = ReleaseKey(application=b"ssh:strugglebus-smoke")
SYSTEMD_IMAGE = "strugglebus-smoke-debian13"
DEBIAN = "strugglebus-smoke-debian"
DOCKER_HOST = "strugglebus-smoke-docker"
# Stands in for the setup page: writes an operator password verifier to the
# path given as its argument. No quotes, so it fits inside a shell string.
SET_PASSWORD = (
    "import os, sys; from strugglebus.operator_auth import create_password_verifier; "
    "fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); "
    "os.write(fd, create_password_verifier(chr(97) * 20)); os.close(fd)"
)
PAGE = '''\
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
folder = sys.argv[1]
names = sorted(os.listdir(folder))
version = [n for n in names if n.endswith(".whl")][0].split("-")[1]
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/latest":
            body = json.dumps({"tag_name": "v" + version, "assets": [
                {"name": n, "browser_download_url": "http://127.0.0.1:8000/files/" + n}
                for n in names]}).encode()
        elif self.path == "/latest/git/ref/tags/v" + version:
            body = json.dumps({"object": {"type": "tag", "sha": "a" * 40}}).encode()
        elif self.path == "/latest/git/tags/" + "a" * 40:
            body = json.dumps({"tag": "v" + version, "message": open(folder + ".tag").read()}).encode()
        elif self.path.startswith("/files/") and self.path[7:] in names:
            body = open(os.path.join(folder, self.path[7:]), "rb").read()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *arguments):
        pass
HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
'''
MIRROR = (
    "RELEASE_API=http://127.0.0.1:8000/latest\\n"
    "RELEASE_DOWNLOAD_PREFIX=http://127.0.0.1:8000/files/\\n"
)


class Failure(Exception):
    pass


def run(*command: str, check: bool = True, timeout: int = 1800, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, cwd=cwd,
        encoding="utf-8", errors="replace",
    )
    output = result.stdout + result.stderr
    if check and result.returncode != 0:
        raise Failure(f"{' '.join(command[:6])} ... failed:\n{output[-3000:]}")
    return output


def inside(container: str, script: str, *, check: bool = True) -> str:
    return run("docker", "exec", container, "bash", "-c", script, check=check)


def expect(condition: bool, what: str, detail: str = "") -> None:
    if not condition:
        raise Failure(f"{what}\n{detail[-3000:]}")
    print(f"  ok  {what}", flush=True)


def trust_smoke_key(fetcher: Path) -> None:
    """Makes a copy of the release fetcher trust this run's key in place of the owner's."""
    text = fetcher.read_text(encoding="utf-8")
    start = text.index("RELEASE_KEYS = (")
    end = text.index("\n)\n", start) + len("\n)\n")
    fetcher.write_bytes(
        (text[:start] + f'RELEASE_KEYS = (\n    "{SMOKE_KEY.blob}",\n)\n' + text[end:]).encode("utf-8"),
    )


def build_wheels(work: Path) -> dict[str, str]:
    """Build current, newer and broken wheels from copies of the source tree."""
    current = re.search(
        r'__version__ = "([^"]+)"',
        (REPOSITORY / "src/strugglebus/__init__.py").read_text(encoding="utf-8"),
    )[1]
    major, minor, patch = (int(part) for part in current.split("."))
    versions = {
        "current": current,
        "newer": f"{major}.{minor}.{patch + 1}",
        "broken": f"{major}.{minor}.{patch + 2}",
    }
    for name, version in versions.items():
        tree = work / f"tree-{name}"
        tree.mkdir()
        shutil.copytree(
            REPOSITORY / "src", tree / "src",
            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"),
        )
        for extra in ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in"):
            if (REPOSITORY / extra).is_file():
                shutil.copy(REPOSITORY / extra, tree / extra)
        init = tree / "src/strugglebus/__init__.py"
        init.write_bytes(init.read_bytes().replace(current.encode(), version.encode()))
        trust_smoke_key(tree / "src/strugglebus/selfhost/fetch_release.py")
        if name == "broken":
            app = tree / "src/strugglebus/app.py"
            text = app.read_text(encoding="utf-8")
            marker = ") -> FastAPI:\n"
            at = text.index(marker, text.index("def create_app(")) + len(marker)
            app.write_bytes(
                (text[:at] + '    raise RuntimeError("smoke test: broken release")\n' + text[at:])
                .encode("utf-8")
            )
        release = work / "share" / name
        release.mkdir(parents=True)
        run("uv", "build", "--wheel", "--out-dir", str(release), cwd=tree)
        shutil.copy(REPOSITORY / "requirements.lock", release / "requirements.lock")
        sums = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(release.iterdir())
        )
        (release / "SHA256SUMS").write_bytes(sums.encode())
        # The publisher's signed statement, served as the release's tag message.
        # Only the release's own files: the build also leaves a .gitignore in the folder.
        statement = statement_for(version, {
            path.name: path.read_bytes() for path in release.iterdir() if not path.name.startswith(".")
        })
        (work / "share" / f"{name}.tag").write_bytes(SMOKE_KEY.tag_message(statement).encode())
    (work / "share" / "page.py").write_bytes(PAGE.encode())
    return versions


def remove(*containers: str) -> None:
    run("docker", "rm", "-f", *containers, check=False)


def debian(share: Path, versions: dict[str, str]) -> None:
    print("Debian / Proxmox install", flush=True)
    dockerfile = (
        "FROM debian:13\n"
        "RUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus "
        "python3 ca-certificates curl iproute2 >/dev/null && apt-get clean\n"
        "STOPSIGNAL SIGRTMIN+3\nCMD [\"/sbin/init\"]\n"
    )
    build = share.parent / "systemd-image"
    build.mkdir()
    (build / "Dockerfile").write_bytes(dockerfile.encode())
    run("docker", "build", "-q", "-t", SYSTEMD_IMAGE, str(build))
    remove(DEBIAN)
    run(
        "docker", "run", "-d", "--name", DEBIAN, "--privileged", "--cgroupns=host",
        "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-v", f"{share}:/src:ro", SYSTEMD_IMAGE,
    )
    time.sleep(6)
    probe = (
        'probe() { curl -s -o /dev/null -w "%{http_code}" --max-time 8 '
        "--cacert /etc/strugglebus/ca-root.crt "
        '--resolve "bus.home.arpa:443:$(hostname -I | cut -d" " -f1)" $1 '
        "https://bus.home.arpa/healthz; }; "
    )
    version = "/opt/strugglebus/venv/bin/strugglebus --version | awk '{print $NF}'"

    out = inside(DEBIAN, (
        "mkdir -p /root/strugglebus && cd /root/strugglebus && cp /src/current/* . && "
        "python3 -m zipfile -e strugglebus-*.whl _wheel && "
        "bash _wheel/strugglebus/selfhost/debian/install.sh --hostname bus.home.arpa 2>&1"
    ))
    expect(f"Strugglebus {versions['current']} is running." in out, "installer finishes", out)
    expect("Auto updates    : on" in out, "automatic updates default to on", out)
    expect(inside(DEBIAN, probe + "probe ''") == "200", "bus is healthy through the gateway")

    out = inside(DEBIAN, probe + "ip addr add 203.0.113.5/32 dev lo; probe '--interface 203.0.113.5'")
    expect(out == "403", "gateway refuses a visitor from a public address", out)

    inside(DEBIAN, (
        f"printf '{MIRROR}' > /etc/strugglebus/update.conf; "
        "systemd-run --quiet --unit smoke-page python3 /src/page.py /src/newer; sleep 1; "
        "strugglebus-update off"
    ))
    inside(DEBIAN, "systemctl start strugglebus-update.service")
    out = inside(DEBIAN, f"strugglebus-update status; {version}")
    expect(
        "Automatic updates : off" in out and out.strip().endswith(versions["current"]),
        "daily check installs nothing while switched off", out,
    )

    inside(DEBIAN, "strugglebus-update on; systemctl start strugglebus-update.service "
        "|| { journalctl -u strugglebus-update.service --no-pager -n 25; exit 1; }")
    out = inside(DEBIAN, f"strugglebus-update status; {version}")
    expect(out.strip().endswith(versions["newer"]), "daily check installs the newer release", out)
    expect(inside(DEBIAN, probe + "probe ''") == "200", "bus is healthy after the update")
    out = inside(DEBIAN, "ls /var/backups/strugglebus | wc -l")
    expect(int(out.strip()) >= 1, "database was backed up before the update", out)

    inside(DEBIAN, (
        "systemctl stop smoke-page; "
        "systemd-run --quiet --unit smoke-page-2 python3 /src/page.py /src/broken; sleep 1"
    ))
    out = inside(DEBIAN, "systemctl start strugglebus-update.service; echo exit=$?", check=False)
    expect("exit=1" in out, "a release that cannot start fails the update", out)
    out = inside(DEBIAN, f"strugglebus-update status; systemctl is-active strugglebus; {version}")
    expect(
        out.strip().endswith(versions["newer"]) and "\nactive\n" in out and "- failed" in out,
        "previous version was put back and is running", out,
    )
    expect(inside(DEBIAN, probe + "probe ''") == "200", "bus is healthy after the put-back")
    out = inside(DEBIAN, "systemctl start strugglebus-update.service; echo exit=$?")
    expect("exit=0" in out, "the failed release is not retried by the next daily check", out)

    # The manual's "Freezing agent access" and "Forgotten operator password".
    out = inside(DEBIAN, "strugglebus-admin access-freeze freeze --reason smoke-test")
    expect(bool(re.search(r'"frozen":\s*true', out)), "command line freezes agent access", out)
    out = inside(DEBIAN, (
        "strugglebus-admin access-freeze unfreeze --reason smoke-test >/dev/null; "
        "strugglebus-admin access-freeze status"
    ))
    expect(bool(re.search(r'"frozen":\s*false', out)), "command line clears the freeze", out)
    out = inside(DEBIAN, (
        f'runuser -u strugglebus -- /opt/strugglebus/venv/bin/python -c "{SET_PASSWORD}" '
        "/var/lib/strugglebus/operator/password && rm -f /var/lib/strugglebus/operator/setup-code && "
        "systemctl restart strugglebus && sleep 6 && strugglebus-info"
    ))
    expect("already set" in out, "a bus with a password offers no setup code", out)
    out = inside(DEBIAN, (
        "systemctl stop strugglebus && rm /var/lib/strugglebus/operator/password && "
        "systemctl start strugglebus && sleep 6 && strugglebus-info"
    ))
    expect(bool(re.search(r"Setup code\s*: [0-9a-f]{24}", out)),
           "deleting the password file brings back a setup code", out)
    expect(inside(DEBIAN, probe + "probe ''") == "200", "bus is healthy after the password reset")


def docker(share: Path, versions: dict[str, str]) -> None:
    print("Docker install", flush=True)
    remove(DOCKER_HOST)
    run(
        "docker", "run", "-d", "--privileged", "--name", DOCKER_HOST,
        "-v", f"{share}:/src:ro", "docker:27-dind",
    )
    time.sleep(12)
    run("docker", "exec", DOCKER_HOST, "sh", "-c", "apk add -q bash python3")
    healthy = (
        "healthy() { for i in $(seq 1 90); do "
        '[ "$(docker inspect --format "{{.State.Health.Status}}" "$(docker compose ps -q bus)" 2>/dev/null)" = healthy ] '
        "&& return 0; sleep 2; done; return 1; }; cd /srv/strugglebus 2>/dev/null; "
    )
    out = inside(DOCKER_HOST, (
        "mkdir -p /srv/strugglebus && cd /srv/strugglebus && cp /src/current/* . && "
        "python3 -m zipfile -e strugglebus-*.whl _wheel && "
        "cp _wheel/strugglebus/selfhost/docker/* _wheel/strugglebus/selfhost/fetch_release.py . && "
        "rm -r _wheel && cp env.example .env && sed -i 's/^BUS_PORT=.*/BUS_PORT=8443/' .env && "
        "docker compose up -d --build >build.log 2>&1 || { tail -30 build.log; exit 1; }; "
        + healthy + "healthy && bash update.sh status"
    ))
    expect(
        f"Installed version : {versions['current']}" in out and "Automatic updates : on" in out,
        "compose install is healthy with updates on", out,
    )

    run("docker", "exec", "-d", DOCKER_HOST, "python3", "/src/page.py", "/src/newer")
    inside(DOCKER_HOST, (
        f"cd /srv/strugglebus && printf '{MIRROR}FETCH_NETWORK=host\\n' > update.conf && "
        "docker compose exec -T bus sh -c 'printf off > /data/bus/selfhost/auto-update'"
    ))
    out = inside(DOCKER_HOST, "cd /srv/strugglebus && bash update.sh check && bash update.sh status")
    expect(
        f"Installed version : {versions['current']}" in out,
        "scheduled check installs nothing while switched off", out,
    )
    out = inside(DOCKER_HOST, (
        "cd /srv/strugglebus && "
        "docker compose exec -T bus sh -c 'printf on > /data/bus/selfhost/auto-update' && "
        "bash update.sh check && bash update.sh status"
    ))
    expect(
        f"Installed version : {versions['newer']}" in out,
        "scheduled check installs the newer release", out,
    )

    inside(DOCKER_HOST, "kill $(pgrep -f 'python3 /src/[p]age')")
    run("docker", "exec", "-d", DOCKER_HOST, "python3", "/src/page.py", "/src/broken")
    time.sleep(2)
    out = inside(DOCKER_HOST, "cd /srv/strugglebus && bash update.sh check; echo exit=$?", check=False)
    expect("exit=1" in out and "was put back and is running" in out,
           "a release that cannot start is replaced by the previous version", out)
    out = inside(DOCKER_HOST, healthy + "healthy && bash update.sh status")
    expect(f"Installed version : {versions['newer']}" in out, "bus is healthy after the put-back", out)
    out = inside(DOCKER_HOST, "cd /srv/strugglebus && bash update.sh check; echo exit=$?")
    expect("exit=0" in out and "not retrying automatically" in out,
           "the failed release is not retried by the next check", out)

    # The manual's "Freezing agent access" and "Forgotten operator password".
    bus = "cd /srv/strugglebus && docker compose exec -T bus "
    out = inside(DOCKER_HOST, bus + "strugglebus access-freeze freeze --reason smoke-test")
    expect(bool(re.search(r'"frozen":\s*true', out)), "command line freezes agent access", out)
    out = inside(DOCKER_HOST, (
        bus + "strugglebus access-freeze unfreeze --reason smoke-test >/dev/null; "
        + bus + "strugglebus access-freeze status"
    ))
    expect(bool(re.search(r'"frozen":\s*false', out)), "command line clears the freeze", out)
    out = inside(DOCKER_HOST, (
        bus + f'/opt/strugglebus/bin/python -c "{SET_PASSWORD}" /data/bus/operator/password && '
        + bus + "rm -f /data/bus/operator/setup-code && docker compose restart bus >/dev/null 2>&1; "
        + healthy + "healthy && docker compose exec -T bus strugglebus-info"
    ))
    expect("already set" in out, "a bus with a password offers no setup code", out)
    out = inside(DOCKER_HOST, (
        bus + "rm /data/bus/operator/password && docker compose restart bus >/dev/null 2>&1; "
        + healthy + "healthy && docker compose exec -T bus strugglebus-info"
    ))
    expect(bool(re.search(r"Setup code\s*: [0-9a-f]{24}", out)),
           "deleting the password file brings back a setup code", out)


def main(arguments: list[str]) -> int:
    chosen = arguments or ["debian", "docker"]
    if any(name not in {"debian", "docker"} for name in chosen):
        print(__doc__)
        return 2
    run("docker", "info", timeout=60)
    with tempfile.TemporaryDirectory(prefix="strugglebus-smoke-") as folder:
        work = Path(folder).resolve()
        try:
            print("Building test wheels", flush=True)
            versions = build_wheels(work)
            if "debian" in chosen:
                debian(work / "share", versions)
            if "docker" in chosen:
                docker(work / "share", versions)
        except Failure as failure:
            print(f"\nFAILED: {failure}", file=sys.stderr)
            return 1
        finally:
            remove(DEBIAN, DOCKER_HOST)
    print("\nAll self-host checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
