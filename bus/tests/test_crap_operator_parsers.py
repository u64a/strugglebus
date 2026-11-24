"""Strict operator parsers: leases, SSH client files, forms, cookies, verifier files."""

import json
import os
from types import SimpleNamespace

import pytest

from strugglebus import operator_auth, operator_fence
from strugglebus.errors import ConfigurationError
from strugglebus.operator_auth import (
    OperatorFormError, PasswordVerifier, create_password_verifier,
    load_password_verifier, operator_cookie, parse_form,
)
from strugglebus.operator_ssh import SSH_ALIAS, parse_ssh_configuration

LEASE = {
    "version": 1, "pid": 4321, "start_ticks": 99, "token": "ab" * 32,
    "lease_seconds": 30, "heartbeat_ns": 123_456_789,
}


def lease_bytes(**changes):
    return json.dumps({**LEASE, **changes}).encode("ascii")


def test_lease_round_trips_exact_fields():
    assert operator_fence.parse_lease(lease_bytes()) == LEASE


@pytest.mark.parametrize("changes", [
    {"version": 2}, {"version": True}, {"version": "1"},
    {"pid": 1}, {"pid": 0}, {"pid": "4321"}, {"pid": True},
    {"start_ticks": 0}, {"start_ticks": 1.5}, {"lease_seconds": -1},
    {"heartbeat_ns": 0}, {"heartbeat_ns": None},
    {"token": "AB" * 32}, {"token": "ab" * 31}, {"token": 7}, {"token": "ab" * 32 + "\n"},
    {"extra": 1},
])
def test_lease_refuses_wrong_types_ranges_and_extra_fields(changes):
    with pytest.raises(ConfigurationError, match="delegation is unavailable"):
        operator_fence.parse_lease(lease_bytes(**changes))


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"null", b"{}", b"\xff", "{\"pid\": \"é\"}".encode("utf-8"),
    b'{"version":1,"version":1}', b"[" * 100_000,
    json.dumps({key: value for key, value in LEASE.items() if key != "token"}).encode(),
    lease_bytes() + b" " * operator_fence.MAX_BINDING_BYTES,
], ids=[
    "empty", "list", "null", "no-fields", "not-ascii", "not-ascii-text",
    "duplicate-field", "too-deep", "missing-token", "oversized",
])
def test_lease_refuses_malformed_duplicate_partial_and_oversized_documents(raw):
    with pytest.raises(ConfigurationError, match="delegation is unavailable"):
        operator_fence.parse_lease(raw)


def stat_line(*, state=b"S", start=b"777", command=b"(python)", fields=22):
    tail = [state] + [b"0"] * 18 + [start] + [b"0"] * (fields - 20)
    return b"4321 " + command + b" " + b" ".join(tail) + b"\n"


def test_start_ticks_are_field_twenty_two_after_the_command_name():
    assert operator_fence._start_ticks_from_stat(stat_line()) == 777
    # A command name may itself contain spaces and parentheses.
    hostile = stat_line(command=b"(a) 1 2 3 (b)", start=b"4242")
    assert operator_fence._start_ticks_from_stat(hostile) == 4242


@pytest.mark.parametrize("raw", [
    stat_line(state=b"Z"), stat_line(state=b"X"),
    b"4321 no-command-name S 0 0", b"4321 (short) S 1 2 3",
    stat_line() + b"0 " * 2100,
], ids=["zombie", "dead", "no-command-name", "truncated", "oversized"])
def test_start_ticks_refuse_dead_truncated_and_oversized_records(raw):
    with pytest.raises(ConfigurationError, match="delegation is unavailable"):
        operator_fence._start_ticks_from_stat(raw)


def test_start_ticks_must_be_numeric():
    with pytest.raises(ValueError):
        operator_fence._start_ticks_from_stat(stat_line(start=b"soon"))


def test_lease_must_match_the_whole_expected_binding():
    assert operator_fence._lease_matches_binding(dict(LEASE), dict(LEASE))
    for name, other in (
        ("token", "cd" * 32), ("pid", 4322), ("start_ticks", 100),
        ("lease_seconds", 31), ("heartbeat_ns", 1),
    ):
        assert not operator_fence._lease_matches_binding(dict(LEASE), {**LEASE, name: other})


def test_heartbeat_must_be_recent_and_not_from_the_future(monkeypatch):
    now = 50_000_000_000
    monkeypatch.setattr(operator_fence, "time", SimpleNamespace(monotonic_ns=lambda: now))
    second = 1_000_000_000
    assert operator_fence._heartbeat_is_fresh({"heartbeat_ns": now, "lease_seconds": 30})
    assert operator_fence._heartbeat_is_fresh(
        {"heartbeat_ns": now - 30 * second + 1, "lease_seconds": 30},
    )
    assert not operator_fence._heartbeat_is_fresh(
        {"heartbeat_ns": now - 30 * second, "lease_seconds": 30},
    )
    assert not operator_fence._heartbeat_is_fresh({"heartbeat_ns": now + 1, "lease_seconds": 30})


@pytest.fixture
def ssh_files(tmp_path):
    return tmp_path / "operator-key", tmp_path / "known-hosts"


def ssh_text(files, *, lines=(), **changes):
    identity, known_hosts = files
    entries = {
        "Host": SSH_ALIAS, "HostName": "bus.example.test", "User": "operator",
        "IdentityFile": f'"{identity}"', "UserKnownHostsFile": f'"{known_hosts}"',
        **changes,
    }
    body = [f"{key} {value}" for key, value in entries.items() if value is not None]
    return "\n".join([*body, *lines]).encode("utf-8")


def test_ssh_configuration_accepts_only_the_fixed_literal_alias_block(ssh_files):
    config = parse_ssh_configuration(
        b"# operator client\n\n" + ssh_text(
            ssh_files, lines=["  port 2222", "\tIdentitiesOnly yes   ", "   # trailing note"],
        ),
    )
    assert (config.hostname, config.user, config.port) == ("bus.example.test", "operator", "2222")
    assert (config.identity_file, config.known_hosts_file) == ssh_files
    assert parse_ssh_configuration(ssh_text(ssh_files)).port == "22"
    bracketed = parse_ssh_configuration(ssh_text(ssh_files, HostName="[fd00::1]"))
    assert bracketed.hostname == "[fd00::1]"


@pytest.mark.parametrize("line,message", [
    ("ProxyCommand none", "unsupported or duplicate"),
    ("User other", "unsupported or duplicate"),
    ("Include extra.conf", "unsupported or duplicate"),
    (f"Host {SSH_ALIAS}", "only the fixed operator SSH alias"),
    ("Port 22 extra", "simple literal entries"),
    ("Port=22", "simple literal entries"),
    ('Port "22', "simple literal entries"),
    ("Port %p", "expansions are forbidden"),
    ("Port $PORT", "expansions are forbidden"),
    ("Port `id`", "expansions are forbidden"),
    ('Port "2\x7f2"', "expansions are forbidden"),
    ("Port 0", "port is invalid"),
    ("Port 65536", "port is invalid"),
    ("Port 123456", "port is invalid"),
    ("IdentitiesOnly no", "host, user or identity policy"),
])
def test_ssh_configuration_refuses_unreviewed_entries(ssh_files, line, message):
    with pytest.raises(ConfigurationError, match=message):
        parse_ssh_configuration(ssh_text(ssh_files, lines=[line]))


@pytest.mark.parametrize("changes,message", [
    ({"Host": "another-alias"}, "only the fixed operator SSH alias"),
    ({"Host": None}, "unsupported or duplicate"),
    ({"HostName": None}, "incomplete"),
    ({"User": None}, "incomplete"),
    ({"IdentityFile": None}, "incomplete"),
    ({"UserKnownHostsFile": None}, "incomplete"),
    ({"HostName": "-oProxyCommand=id"}, "host, user or identity policy"),
    ({"HostName": "bus/evil"}, "host, user or identity policy"),
    ({"User": "Root"}, "host, user or identity policy"),
    ({"User": "-l"}, "host, user or identity policy"),
    ({"IdentityFile": "relative-key"}, "distinct absolute paths"),
    ({"UserKnownHostsFile": "relative-hosts"}, "distinct absolute paths"),
])
def test_ssh_configuration_refuses_wrong_alias_missing_and_unsafe_values(
    ssh_files, changes, message,
):
    with pytest.raises(ConfigurationError, match=message):
        parse_ssh_configuration(ssh_text(ssh_files, **changes))


def test_ssh_configuration_refuses_shared_file_alias_after_settings_and_bad_encoding(ssh_files):
    identity, _ = ssh_files
    with pytest.raises(ConfigurationError, match="distinct absolute paths"):
        parse_ssh_configuration(ssh_text(ssh_files, UserKnownHostsFile=f'"{identity}"'))
    with pytest.raises(ConfigurationError, match="unsupported or duplicate"):
        parse_ssh_configuration(b"HostName bus.example.test\n" + ssh_text(ssh_files))
    with pytest.raises(ConfigurationError, match="too large"):
        parse_ssh_configuration(ssh_text(ssh_files) + b"\n" + b"#" * 8192)
    with pytest.raises(ConfigurationError, match="must be UTF-8"):
        parse_ssh_configuration(ssh_text(ssh_files) + b"\n# \xff")


def test_form_decodes_each_component_once_and_allows_optional_fields():
    assert parse_form(
        b"na%6De=a%3Db%26c&csrf=x", allowed={"name", "csrf", "note"},
        required={"csrf"}, maximum=8192,
    ) == {"name": "a=b&c", "csrf": "x"}
    assert parse_form(b"csrf=", allowed={"csrf"}, required={"csrf"}, maximum=8192) == {"csrf": ""}


@pytest.mark.parametrize("body", [
    b"", b"other=x", b"%zzcsrf=x", b"csrf=x&note=y&csrf=z", b"cs%ffrf=x", b"note=only",
])
def test_form_refuses_missing_required_unknown_and_undecodable_keys(body):
    with pytest.raises(OperatorFormError, match="invalid operator form"):
        parse_form(body, allowed={"csrf", "note"}, required={"csrf"}, maximum=8192)


TOKEN = "t" * 43


def cookie(value: bytes):
    return [(b"host", b"bus.test"), (b"Cookie", value)]


def test_cookie_is_found_among_other_cookies():
    header = f"theme=dark; session={TOKEN} ; other=1".encode("ascii")
    assert operator_cookie(cookie(header), "session") == TOKEN
    assert operator_cookie(cookie(header), "absent") is None
    assert operator_cookie([(b"host", b"bus.test")], "session") is None


@pytest.mark.parametrize("header", [
    f"session={TOKEN}; session={TOKEN}", "session", "session; other=1",
    "session=short", f"session={TOKEN}=", f"session={TOKEN[:-1]}!", f"session= {TOKEN}",
])
def test_cookie_refuses_duplicates_bare_names_and_malformed_tokens(header):
    assert operator_cookie(cookie(header.encode("ascii")), "session") is None


def test_cookie_refuses_repeated_headers_and_non_ascii_bytes():
    header = f"session={TOKEN}".encode("ascii")
    assert operator_cookie([(b"cookie", header), (b"COOKIE", header)], "session") is None
    assert operator_cookie(cookie(header + b"; note=\xff"), "session") is None


PASSWORD = "synthetic verifier file password"


@pytest.fixture
def verifier_file(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    path = tmp_path / "operator-password"
    path.write_bytes(create_password_verifier(PASSWORD))
    path.chmod(0o600)
    # A service-owned credentials directory is what lets a non-root runtime
    # user own the verifier; without it only root ownership is accepted.
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    return path


def test_verifier_file_loads_from_a_private_regular_file(verifier_file):
    loaded = load_password_verifier(verifier_file)
    assert isinstance(loaded, PasswordVerifier)
    assert loaded.verify(PASSWORD)
    assert not loaded.verify(PASSWORD + "x")


def test_verifier_file_refuses_directories_and_extra_hard_links(verifier_file):
    with pytest.raises(ConfigurationError, match="unsafe operator credential file"):
        load_password_verifier(verifier_file.parent)
    try:
        os.link(verifier_file, verifier_file.with_name("second-name"))
    except OSError:
        pytest.skip("hard links are unavailable here")
    with pytest.raises(ConfigurationError, match="unsafe operator credential file"):
        load_password_verifier(verifier_file)


def test_verifier_file_refuses_symbolic_links(verifier_file):
    link = verifier_file.with_name("linked-password")
    try:
        link.symlink_to(verifier_file)
    except OSError:
        pytest.skip("symbolic links are unavailable here")
    with pytest.raises(ConfigurationError, match="unsafe operator credential file"):
        load_password_verifier(link)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
def test_verifier_file_refuses_shared_modes_and_unprotected_directories(
    verifier_file, monkeypatch,
):
    verifier_file.chmod(0o640)
    with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
        load_password_verifier(verifier_file)
    verifier_file.chmod(0o600)
    if os.geteuid() != 0:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY")
        with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
            load_password_verifier(verifier_file)


class DescriptorSpy:
    """Observe the one descriptor load_password_verifier opens for its source."""

    def __init__(self, monkeypatch, path, *, substitute=None):
        self.path, self.substitute, self.descriptor = path, substitute, None
        self._open, self._read = os.open, os.read
        self.on_read = lambda data: data
        monkeypatch.setattr(operator_auth.os, "open", self.open)
        monkeypatch.setattr(operator_auth.os, "read", self.read)

    def open(self, path, flags, *args, **kwargs):
        if path != self.path:
            return self._open(path, flags, *args, **kwargs)
        self.descriptor = self._open(self.substitute or path, flags, *args, **kwargs)
        return self.descriptor

    def read(self, descriptor, count):
        if descriptor != self.descriptor:
            return self._read(descriptor, count)
        return self.on_read(self._read(descriptor, count))

    def closed(self):
        try:
            os.fstat(self.descriptor)
        except OSError:
            return True
        return False


def test_verifier_file_refuses_a_source_replaced_before_open(verifier_file, monkeypatch):
    other = verifier_file.with_name("replacement")
    other.write_bytes(create_password_verifier("a different password"))
    other.chmod(0o600)
    spy = DescriptorSpy(monkeypatch, verifier_file, substitute=other)
    with pytest.raises(ConfigurationError, match="operator credential file changed"):
        load_password_verifier(verifier_file)
    assert spy.closed()


def test_verifier_file_refuses_a_source_modified_while_read(verifier_file, monkeypatch):
    spy = DescriptorSpy(monkeypatch, verifier_file)

    def modify(data):
        with verifier_file.open("ab") as stream:
            stream.write(b"\n")
        return data

    spy.on_read = modify
    with pytest.raises(ConfigurationError, match="operator credential file changed"):
        load_password_verifier(verifier_file)
    assert spy.closed()


def test_verifier_file_read_failure_is_reported_and_descriptor_closed(
    verifier_file, monkeypatch,
):
    spy = DescriptorSpy(monkeypatch, verifier_file)

    def fail(data):
        raise OSError("synthetic read failure")

    spy.on_read = fail
    with pytest.raises(ConfigurationError, match="operator credential file is unreadable"):
        load_password_verifier(verifier_file)
    assert spy.closed()


def test_verifier_file_content_must_be_one_exact_verifier(verifier_file):
    verifier_file.write_bytes(b"sbop1$600000$not-a-verifier\n")
    with pytest.raises(ConfigurationError):
        load_password_verifier(verifier_file)
