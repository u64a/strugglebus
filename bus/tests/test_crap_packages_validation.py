"""Reconnect and onboarding packages, enrollment limits and credential identities."""

import hashlib
import io
import json
import os
import secrets
import ssl
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from urllib.error import HTTPError

import pytest

from test_ca_anchor import chain  # noqa: F401
from strugglebus import reconnect
from strugglebus.auth import (
    mint_mobile_write_grant, mint_spn_enrollment_token, parse_credential,
    parse_mobile_write_grant,
)
from strugglebus.errors import ConfigurationError, DomainValidationError
from strugglebus.models import LifecycleActor
from strugglebus.reconnect import (
    MAX_REDEMPTION_RESPONSE_BYTES, ReconnectError, decode_package, encode_package,
    redeem_package,
)
from strugglebus.roe import RoeService
from strugglebus.spn import (
    MAX_IDENTITY_TTL_SECONDS, ServicePrincipalService, encode_onboarding_package,
)

INVALID = "reconnect package is invalid or expired"
OTHER_ID = "7d3b0c52-6a51-4f6e-9a35-0f8f6f1f2a44"


@pytest.fixture
def anchor(chain):  # noqa: F811
    pem = (chain / "root.crt").read_bytes()
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))).hexdigest()
    return pem, digest


@pytest.fixture
def package_data(anchor):
    pem, digest = anchor
    return {
        "agent_id": str(uuid.uuid4()), "agent_name": "synthetic-recipient",
        "base_url": "https://bus.test", "ca_root": pem, "ca_sha256": digest,
        "expires_at": datetime.now(UTC) + timedelta(seconds=800),
        "grant": f"sbr1_{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}",
    }


@pytest.fixture
def payload(package_data):
    return json.loads(encode_package(**package_data))


def encoded(value):
    return json.dumps(value).encode("utf-8")


def test_package_keeps_an_explicit_port_and_strips_only_a_trailing_slash(package_data):
    raw = encode_package(**{**package_data, "base_url": "https://bus.test:8443/"})
    package = decode_package(raw)
    assert package.base_url == "https://bus.test:8443"
    assert package.expires_at == package_data["expires_at"]
    assert package.ca_root == package_data["ca_root"]


@pytest.mark.parametrize("change", [
    {"version": "1"}, {"version": 1.0}, {"grant": 5}, {"agent_id": None},
    {"unexpected": "field"},
    {"agent_id": "not-a-uuid"}, {"agent_id": OTHER_ID.upper()},
    {"agent_id": OTHER_ID.replace("-", "")},
    {"agent_name": "Synthetic-Recipient"}, {"agent_name": "solo"},
    {"agent_name": "a-" + "b" * 127},
    {"base_url": "https://bus.test/" + "a" * 2048},
    {"base_url": "https://büs.test"}, {"base_url": "https://bus.test "},
    {"base_url": "https://bus\x7f.test"},
    {"base_url": "http://bus.test"}, {"base_url": "https://"},
    {"base_url": "https://user@bus.test"}, {"base_url": "https://:secret@bus.test"},
    {"base_url": "https://bus.test/api"}, {"base_url": "https://bus.test?next=1"},
    {"base_url": "https://bus.test#fragment"}, {"base_url": "https://bus.test:0"},
    {"base_url": "https://bus.test:99999"}, {"base_url": "https://bus.test:port"},
    {"expires_at": "soon"}, {"expires_at": "2099-01-01T00:00:00"},
    {"grant": "sbr1_short_grant"}, {"grant": ""},
    {"ca_root": "-----BEGIN CERTIFICATE-----\né\n-----END CERTIFICATE-----\n"},
    {"ca_root": "not a certificate"}, {"ca_sha256": "f" * 64}, {"ca_sha256": "F" * 64},
], ids=lambda change: "-".join(change) + "-" + repr(next(iter(change.values())))[:24])
def test_package_refuses_each_invalid_field(payload, change):
    with pytest.raises(ConfigurationError, match=INVALID):
        decode_package(encoded({**payload, **change}))


@pytest.mark.parametrize("field", [
    "version", "agent_id", "agent_name", "base_url", "ca_root", "ca_sha256",
    "expires_at", "grant",
])
def test_package_refuses_any_missing_field(payload, field):
    del payload[field]
    with pytest.raises(ConfigurationError, match=INVALID):
        decode_package(encoded(payload))


@pytest.mark.parametrize("raw", [
    b"[]", b"null", b'"package"', b"\xff\xfe", b"{", b"[" * 100_000,
], ids=["list", "null", "text", "not-utf8", "truncated", "too-deep"])
def test_package_refuses_documents_that_are_not_one_object(raw):
    with pytest.raises(ConfigurationError, match=INVALID):
        decode_package(raw)


def test_package_expiry_must_be_utc_unexpired_and_within_the_grant_window(payload):
    now = datetime(2030, 1, 1, tzinfo=UTC)

    def at(expiry):
        return encoded({**payload, "expires_at": expiry.isoformat()})

    assert decode_package(at(now + timedelta(seconds=900)), now=now).expires_at == (
        now + timedelta(seconds=900)
    )
    assert decode_package(at(now + timedelta(seconds=1)), now=now).agent_id == payload["agent_id"]
    offset = (now + timedelta(seconds=600)).astimezone(timezone(timedelta(hours=1)))
    for expiry in (
        now, now - timedelta(seconds=1), now + timedelta(seconds=901),
        (now + timedelta(seconds=600)).replace(tzinfo=None), offset,
    ):
        with pytest.raises(ConfigurationError, match=INVALID):
            decode_package(at(expiry), now=now)


def test_package_cannot_be_prepared_from_unencodable_or_invalid_material(package_data):
    with pytest.raises(ConfigurationError, match="could not be prepared"):
        encode_package(**{**package_data, "ca_root": "certificat é".encode("utf-8")})
    with pytest.raises(ConfigurationError, match=INVALID):
        encode_package(**{**package_data, "base_url": "https://bus.test/api/"})
    with pytest.raises(ConfigurationError, match=INVALID):
        encode_package(**{
            **package_data, "expires_at": datetime.now(UTC) + timedelta(seconds=901),
        })


@pytest.fixture
def package(package_data):
    return decode_package(encode_package(**package_data))


def redemption(package, **changes):
    secret = f"sb1_{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    parsed = parse_credential(secret)
    assert parsed is not None and parsed[0] == "sb1"
    value = {
        "agent": {"id": package.agent_id, "name": package.agent_name},
        "credential": {
            "id": parsed[1], "agent_id": package.agent_id, "kind": "sb1", "status": "pending",
        },
        "credential_secret": secret,
    }
    for path, changed in changes.items():
        target = value
        *parents, leaf = path.split("__")
        for parent in parents:
            target = target[parent]
        target[leaf] = changed
    return value, secret


def test_response_yields_the_pending_secret_for_the_packaged_agent(package):
    value, secret = redemption(package)
    assert reconnect._credential_from_response(encoded(value), package) == secret


@pytest.mark.parametrize("change", [
    {"agent": None}, {"agent": ["agent"]}, {"credential": "sb1"},
    {"agent__id": OTHER_ID}, {"agent__name": "foreign-agent"},
    {"credential__agent_id": OTHER_ID},
    {"credential__kind": "sbm1"}, {"credential__status": "active"},
    {"credential__id": "crd_" + "A" * 22},
    {"credential_secret": None}, {"credential_secret": 7},
    {"credential_secret": "sb1_not-a-credential"},
    {"credential_secret": f"sbr1_{'A' * 22}_{'A' * 43}"},
], ids=lambda change: next(iter(change)))
def test_response_for_another_identity_or_state_is_refused(package, change):
    value, _ = redemption(package, **change)
    with pytest.raises(ValueError, match="identity or pending credential mismatch"):
        reconnect._credential_from_response(encoded(value), package)


def test_response_must_be_one_bounded_object_without_duplicates(package):
    value, _ = redemption(package)
    with pytest.raises(ValueError, match="oversized response"):
        reconnect._credential_from_response(
            encoded(value) + b" " * MAX_REDEMPTION_RESPONSE_BYTES, package,
        )
    with pytest.raises(ValueError, match="invalid response"):
        reconnect._credential_from_response(encoded([value]), package)
    with pytest.raises(ValueError, match="duplicate JSON field"):
        reconnect._credential_from_response(
            encoded(value)[:-1] + b',"agent":{}}', package,
        )
    with pytest.raises(ValueError):
        reconnect._credential_from_response(b"\xff", package)


@pytest.fixture
def package_file(tmp_path, package_data):
    tmp_path.chmod(0o700)
    path = tmp_path / "private-package.json"
    path.write_bytes(encode_package(**package_data))
    path.chmod(0o600)
    return path


class OsProxy:
    """Stand in for the module's os with selected calls replaced."""

    def __init__(self, **replacements):
        self._replacements = replacements

    def __getattr__(self, name):
        return self._replacements.get(name) or getattr(os, name)


def test_redemption_completes_a_credential_written_in_pieces(
    package_file, package, tmp_path, monkeypatch,
):
    value, secret = redemption(package)
    output = tmp_path / "credential"
    monkeypatch.setattr(reconnect, "os", OsProxy(
        write=lambda descriptor, view: os.write(descriptor, view[:7]),
    ))
    redeem_package(package_file, output, exchange=lambda *_: encoded(value))
    assert output.read_bytes() == secret.encode("ascii") + b"\n"


def test_stalled_credential_write_leaves_no_partial_output(
    package_file, package, tmp_path, monkeypatch,
):
    value, _ = redemption(package)
    output = tmp_path / "credential"
    monkeypatch.setattr(reconnect, "os", OsProxy(write=lambda descriptor, view: 0))
    with pytest.raises(ReconnectError, match="reconnect failed or its result is uncertain"):
        redeem_package(package_file, output, exchange=lambda *_: encoded(value))
    assert not output.exists()


def test_output_removed_during_the_exchange_is_not_recreated(package_file, package, tmp_path):
    value, _ = redemption(package)
    output = tmp_path / "credential"

    def exchange(*_):
        if os.name == "nt":
            pytest.skip("an open reserved output cannot be unlinked on Windows")
        output.unlink()
        return encoded(value)

    with pytest.raises(ReconnectError, match="reconnect failed or its result is uncertain"):
        redeem_package(package_file, output, exchange=exchange)
    assert not output.exists()


def test_output_replaced_during_the_exchange_is_neither_written_nor_removed(
    package_file, package, tmp_path,
):
    value, secret = redemption(package)
    output = tmp_path / "credential"

    def exchange(*_):
        if os.name == "nt":
            pytest.skip("an open reserved output cannot be replaced on Windows")
        output.unlink()
        output.write_bytes(b"planted")
        output.chmod(0o600)
        return encoded(value)

    with pytest.raises(ReconnectError, match="private output changed; it was not removed"):
        redeem_package(package_file, output, exchange=exchange)
    assert output.read_bytes() == b"planted"
    assert secret.encode("ascii") not in output.read_bytes()


def test_failed_cleanup_of_the_reserved_output_is_reported(
    package_file, tmp_path, monkeypatch,
):
    output = tmp_path / "credential"

    def cleanup(path, identity):
        assert path == output
        raise PermissionError("synthetic cleanup failure")

    monkeypatch.setattr(reconnect, "_remove_reserved_output", cleanup)
    with pytest.raises(ReconnectError, match="private output cleanup failed"):
        redeem_package(package_file, output, exchange=lambda *_: b"not json")


def test_reserved_output_cleanup_tolerates_absence_and_spares_other_files(tmp_path):
    path = tmp_path / "credential"
    reconnect._remove_reserved_output(path, (1, 2))
    path.write_bytes(b"other")
    metadata = path.lstat()
    with pytest.raises(ReconnectError, match="it was not removed"):
        reconnect._remove_reserved_output(path, (metadata.st_dev, metadata.st_ino + 1))
    assert path.read_bytes() == b"other"
    reconnect._remove_reserved_output(path, (metadata.st_dev, metadata.st_ino))
    assert not path.exists()


def onboarding(anchor, **changes):
    pem, digest = anchor
    _, _, token = mint_spn_enrollment_token()
    arguments = {
        "agent_name": "build-cli-win", "base_url": "https://bus.test", "ca_root": pem,
        "ca_sha256": digest, "expires_at": datetime(2030, 1, 1, tzinfo=UTC),
        "enrollment_token": token, **changes,
    }
    return arguments, encode_onboarding_package(**arguments)


def test_onboarding_package_carries_canonical_name_origin_and_anchor(anchor):
    arguments, package = onboarding(
        anchor, agent_name=" Build CLI Win ", base_url="https://bus.test:8443//",
    )
    assert package == {
        "version": 1, "agent_name": "build-cli-win", "base_url": "https://bus.test:8443",
        "redeem_path": "/api/enrollments/redeem", "ca_root": anchor[0].decode("ascii"),
        "ca_sha256": anchor[1], "expires_at": "2030-01-01T00:00:00+00:00",
        "enrollment_token": arguments["enrollment_token"],
    }


@pytest.mark.parametrize("change", [
    {"agent_name": "solo"}, {"agent_name": ""},
    {"base_url": "http://bus.test"}, {"base_url": "https://"},
    {"base_url": "https://user@bus.test"}, {"base_url": "https://:secret@bus.test"},
    {"base_url": "https://bus.test/api"}, {"base_url": "https://bus.test?next=1"},
    {"base_url": "https://bus.test#fragment"}, {"base_url": "https://büs.test"},
    {"ca_sha256": "0" * 64}, {"ca_root": b"not a certificate"},
    {"enrollment_token": "sbse1_malformed"}, {"enrollment_token": ""},
], ids=lambda change: "-".join(change) + "-" + repr(next(iter(change.values())))[:24])
def test_onboarding_package_refuses_unsafe_origin_name_anchor_or_token(anchor, change):
    with pytest.raises(ConfigurationError, match="onboarding package could not be prepared"):
        onboarding(anchor, **change)


@pytest.fixture
def spn(agent_service):
    service = ServicePrincipalService(agent_service.store)
    issued = service.create(
        name="build-onboarder", agent_name_prefix="build-team",
        request_id=str(uuid.uuid4()), actor=LifecycleActor("local-admin", "test-operator"),
    )
    identity = service.authorize(issued.secret)
    assert identity is not None and identity.agent_name_prefix == "build-team"
    return service, identity


def issue(spn, **changes):
    service, identity = spn
    arguments = {"request_id": str(uuid.uuid4()), "agent_name": "build-team-cli", **changes}
    return service.issue_onboarding(arguments.pop("identity", identity), **arguments)


def test_onboarding_is_issued_once_within_the_prefix(spn):
    request_id = str(uuid.uuid4())
    first = issue(spn, request_id=request_id, identity_ttl_seconds=60)
    assert first.secret_issued and first.token is not None
    assert first.agent_name == "build-team-cli"
    assert first.expires_at - first.created_at == timedelta(seconds=300)
    replay = issue(spn, request_id=request_id, identity_ttl_seconds=60)
    assert (replay.enrollment_id, replay.token, replay.secret_issued) == (
        first.enrollment_id, None, False,
    )
    exact = issue(spn, agent_name="Build Team", ttl_seconds=60)
    assert exact.agent_name == "build-team"
    assert exact.expires_at - exact.created_at == timedelta(seconds=60)


@pytest.mark.parametrize("ttl", [59, MAX_IDENTITY_TTL_SECONDS + 1, True, "3600", 60.0])
def test_onboarding_refuses_identity_lifetimes_outside_the_limit(spn, ttl):
    with pytest.raises(ConfigurationError, match="identity_ttl_seconds must be between 60 and 43200"):
        issue(spn, identity_ttl_seconds=ttl)


@pytest.mark.parametrize("name", ["build-teams-cli", "build-cli", "other-team-cli", "build-tea"])
def test_onboarding_refuses_names_outside_the_prefix(spn, name):
    with pytest.raises(ConfigurationError, match="agent name is outside the SPN prefix"):
        issue(spn, agent_name=name)


def test_onboarding_refuses_other_invalid_requests(spn):
    service, identity = spn
    with pytest.raises(ConfigurationError, match="SPN identity is required"):
        issue(spn, identity="build-onboarder")
    with pytest.raises(DomainValidationError):
        issue(spn, agent_name="solo")
    with pytest.raises(ConfigurationError, match="description is invalid"):
        issue(spn, description="x" * 1025)
    with pytest.raises(ConfigurationError, match="ttl_seconds must be between 60 and 300"):
        issue(spn, ttl_seconds=301)
    with pytest.raises(ConfigurationError, match="request_id must be a canonical UUID"):
        issue(spn, request_id="not-a-uuid")
    prepared = service.prepare_onboarding()
    for forged in (
        replace(prepared, secret_hash="0" * 64),
        replace(prepared, enrollment_id="sen_" + "A" * 22),
        replace(prepared, token="sbse1_malformed"),
    ):
        with pytest.raises(ConfigurationError, match="invalid prepared onboarding material"):
            issue(spn, prepared=forged)
    assert issue(spn, prepared=prepared).token == prepared.token


def test_enrollment_names_are_prefixes_or_complete_exact_names(agent_service):
    prefix = agent_service.create_enrollment(name_prefix=" Build ").enrollment
    assert (prefix.name_prefix, prefix.name_match, prefix.uses_allowed) == ("build", "prefix", 1)
    assert prefix.expires_at - prefix.created_at == timedelta(
        seconds=agent_service.enrollment_ttl_seconds,
    )
    exact = agent_service.create_enrollment(
        name_prefix="Build-CLI", name_match="exact", ttl_seconds=60,
    ).enrollment
    assert (exact.name_prefix, exact.name_match) == ("build-cli", "exact")
    assert exact.expires_at - exact.created_at == timedelta(seconds=60)
    with pytest.raises(ConfigurationError, match="exact enrollment requires a complete agent name"):
        agent_service.create_enrollment(name_prefix="build", name_match="exact")
    with pytest.raises(ConfigurationError, match="name_prefix must be lowercase kebab-case"):
        agent_service.create_enrollment(name_prefix="-build")


@pytest.mark.parametrize("name_match", ["glob", "", None, 1])
def test_enrollment_refuses_unknown_match_modes_first(agent_service, name_match):
    with pytest.raises(ConfigurationError, match="name_match must be prefix or exact"):
        agent_service.create_enrollment(name_prefix="-invalid-", name_match=name_match)


@pytest.mark.parametrize("field,value,message", [
    ("uses", 0, "uses must be a positive integer"),
    ("uses", True, "uses must be a positive integer"),
    ("uses", "1", "uses must be a positive integer"),
    ("uses", 1.0, "uses must be a positive integer"),
    ("uses", 2, "uses must not exceed 1"),
    ("ttl_seconds", 0, "ttl_seconds must be a positive integer"),
    ("ttl_seconds", True, "ttl_seconds must be a positive integer"),
    ("ttl_seconds", "60", "ttl_seconds must be a positive integer"),
    ("ttl_seconds", 901, "ttl_seconds must not exceed 900"),
])
def test_enrollment_refuses_uses_and_lifetimes_outside_the_limits(
    agent_service, field, value, message,
):
    with pytest.raises(ConfigurationError, match=message):
        agent_service.create_enrollment(name_prefix="build", **{field: value})


def test_credential_identity_joins_bounded_kind_and_identifier():
    assert RoeService._credential_identity("sb1", "crd_example") == "sb1:crd_example"
    assert len(RoeService._credential_identity("k" * 64, "i" * 191)) == 256


@pytest.mark.parametrize("kind,identifier", [
    ("", "crd_example"), ("sb1", ""), (None, "crd_example"), ("sb1", None), (1, 2),
    ("k" * 65, "crd_example"), ("sb1", "i" * 257), ("sb\x001", "crd_example"),
    ("sb1", "crd\x00example"), ("k" * 64, "i" * 192),
])
def test_credential_identity_refuses_empty_oversized_or_nul_parts(kind, identifier):
    with pytest.raises(DomainValidationError, match="credential context is invalid"):
        RoeService._credential_identity(kind, identifier)


@pytest.mark.parametrize("value", [
    None, 7, b"sb1_bytes", "", "x" * 257, "legacy-crédential",
    "sb1_not-a-current-credential", "sbe1_reserved", "sbsp1_reserved", "sbmw1_reserved",
])
def test_agent_credential_parser_refuses_non_text_oversized_and_reserved_values(value):
    assert parse_credential(value) is None


def test_agent_credential_parser_separates_current_and_legacy_secrets():
    current = f"sb1_{'A' * 22}_{'B' * 43}"
    kind, credential_id, verifier = parse_credential(current)
    assert (kind, credential_id) == ("sb1", "cred_" + "A" * 22)
    legacy = parse_credential("an-older-opaque-secret")
    assert legacy is not None and legacy[1] is None
    assert legacy[2] == hashlib.sha256(b"an-older-opaque-secret").hexdigest()
    assert legacy[0] != kind and legacy[2] != verifier


def test_mobile_write_grant_proves_only_the_device_it_was_minted_for():
    verifier, grant = mint_mobile_write_grant("device-one")
    assert parse_mobile_write_grant(grant, "device-one") == verifier
    other = parse_mobile_write_grant(grant, "device-two")
    assert other is not None and other != verifier
    for value in (None, "", grant + "x" * 257, grant[:-1], "sbm1_" + grant[6:]):
        assert parse_mobile_write_grant(value, "device-one") is None
    for device in (None, "", "d" * 257, 7):
        assert parse_mobile_write_grant(grant, device) is None
    assert parse_credential(grant) is None


class RedemptionResponse:
    def __init__(self, status, body):
        self.status, self.body, self.closed = status, body, False

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.closed = True
        return False

    def read(self, count):
        return self.body[:count]


def exchange(monkeypatch, outcome):
    seen = {}

    class Opener:
        def open(self, request, timeout):
            seen["timeout"] = timeout
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    def build(*handlers):
        seen["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(reconnect, "build_opener", build)
    return reconnect._exchange(
        reconnect.Request("https://bus.test/api/reconnect/redeem"),
        ssl.create_default_context(),
    ), seen


def test_exchange_returns_only_a_created_bounded_response_without_proxy_or_redirect(
    monkeypatch,
):
    response = RedemptionResponse(201, b'{"credential_secret":"synthetic"}')
    body, seen = exchange(monkeypatch, response)
    assert body == b'{"credential_secret":"synthetic"}'
    assert response.closed
    assert seen["timeout"] == reconnect.REDEMPTION_TIMEOUT_SECONDS
    proxy, https, redirect = seen["handlers"]
    assert isinstance(proxy, reconnect.ProxyHandler) and not getattr(proxy, "proxies", {})
    assert isinstance(https, reconnect.HTTPSHandler)
    assert isinstance(redirect, reconnect.NoRedirectHandler)


@pytest.mark.parametrize("status,body,message", [
    (200, b"{}", "server response was inconclusive; the result is uncertain"),
    (204, b"", "server response was inconclusive; the result is uncertain"),
    (
        201, b" " * (MAX_REDEMPTION_RESPONSE_BYTES + 1),
        "response is invalid and the result is uncertain",
    ),
], ids=["ok-not-created", "no-content", "oversized"])
def test_exchange_treats_unexpected_success_shapes_as_uncertain(
    monkeypatch, status, body, message,
):
    response = RedemptionResponse(status, body)
    with pytest.raises(ReconnectError, match=message) as caught:
        exchange(monkeypatch, response)
    assert caught.value.outcome == "unknown" and caught.value.http_status is None
    assert "do not retry this package" in str(caught.value)
    assert response.closed


def test_exchange_reports_an_unlisted_client_refusal_as_definite(monkeypatch):
    refusal = HTTPError(
        "https://bus.test/api/reconnect/redeem", 302, "untrusted detail", {},
        io.BytesIO(b"untrusted body"),
    )
    with pytest.raises(ReconnectError, match=r"http_rejected \(HTTP 302\)") as caught:
        exchange(monkeypatch, refusal)
    assert (caught.value.outcome, caught.value.http_status) == ("rejected", 302)
    assert "untrusted" not in str(caught.value)
