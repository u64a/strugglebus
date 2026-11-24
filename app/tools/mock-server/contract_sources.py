"""Ground mock invariants in machine-generated StruggleBus contract sources.

The deployed OpenAPI document supplies response-model shapes and the integration guide supplies
numeric limits. Behavioral claims remain separately evidenced in contract-provenance.json.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_FIXTURE = ROOT / "fixtures" / "strugglebus-contract-source.json"


def _schema(document: dict[str, Any], name: str) -> dict[str, Any]:
    return document["components"]["schemas"][name]


def extract(openapi: dict[str, Any], guide: dict[str, Any]) -> dict[str, Any]:
    """Extract the source-owned shapes and limits relevant to this POC."""
    return {
        "openapi": openapi["openapi"],
        "service_version": openapi["info"]["version"],
        "guide_version": guide["guide_version"],
        "schemas": {
            "RedeemedEnrollmentResponse": _schema(openapi, "RedeemedEnrollmentResponse"),
            "IssuedCredentialResponse": _schema(openapi, "IssuedCredentialResponse"),
            "MobileWriteGrantRequest": _schema(openapi, "MobileWriteGrantRequest"),
            "MobileWriteGrantResponse": _schema(openapi, "MobileWriteGrantResponse"),
            "MobileConfirmationRequest": _schema(openapi, "MobileConfirmationRequest"),
            "MobileConfirmationResponse": _schema(openapi, "MobileConfirmationResponse"),
            "MobileActionRequest": _schema(openapi, "MobileActionRequest"),
            "MobileActionResponse": _schema(openapi, "MobileActionResponse"),
        },
        "limits": guide["limits"],
    }


def validate(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    schemas = bundle.get("schemas", {})

    redemption = schemas.get("RedeemedEnrollmentResponse", {})
    redemption_properties = redemption.get("properties", {})
    redemption_secret = redemption_properties.get("credential_secret")
    if redemption_secret != {"type": "string", "title": "Credential Secret"}:
        errors.append("redemption credential_secret must be a non-nullable string")
    if "credential_secret" not in redemption.get("required", []):
        errors.append("redemption credential_secret must be required")
    if "secret_issued" in redemption_properties:
        errors.append("redemption must not expose replay-style secret_issued state")

    issued = schemas.get("IssuedCredentialResponse", {})
    issued_properties = issued.get("properties", {})
    issued_secret = issued_properties.get("credential_secret", {})
    variants = issued_secret.get("anyOf", [])
    variant_types = {variant.get("type") for variant in variants}
    if variant_types != {"string", "null"}:
        errors.append("idempotent credential issuance must represent a nullable secret")
    secret_issued = issued_properties.get("secret_issued", {})
    if secret_issued.get("type") != "boolean":
        errors.append("idempotent credential issuance must expose secret_issued")
    required = set(issued.get("required", []))
    if not {"credential_secret", "secret_issued"}.issubset(required):
        errors.append("credential_secret and secret_issued must both be required")

    required_mobile_fields = {
        "MobileWriteGrantRequest": {"request_id", "operator_password", "reason"},
        "MobileWriteGrantResponse": {"device_id", "grant_secret", "guidance"},
        "MobileConfirmationRequest": {"request_id", "action", "target_id"},
        "MobileConfirmationResponse": {
            "confirmation_id", "action", "target_kind", "target_id", "target_label",
            "expires_at", "effect",
        },
        "MobileActionRequest": {
            "request_id", "confirmation_id", "action", "target_id", "grant_secret", "reason",
        },
        "MobileActionResponse": {
            "action", "target_id", "target_label", "applied", "detail",
        },
    }
    for schema_name, expected_fields in required_mobile_fields.items():
        schema = schemas.get(schema_name, {})
        if set(schema.get("required", [])) != expected_fields:
            errors.append(f"{schema_name} required fields changed")
        if schema.get("additionalProperties") is not False:
            errors.append(f"{schema_name} must reject unknown fields")

    limits = bundle.get("limits", {})
    expected_limits = {
        "sse_connection_seconds": 300,
        "sse_max_connections_per_agent": 3,
        "max_read_results": 200,
        "authenticated_requests_per_minute": 600,
        "max_message_bytes": 1_048_576,
        "max_metadata_bytes": 16_384,
    }
    for name, expected in expected_limits.items():
        actual = limits.get(name)
        if actual != expected:
            errors.append(f"{name} changed: expected {expected}, got {actual!r}")
    return errors


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openapi", type=Path, help="Fresh /openapi.json response")
    parser.add_argument("--guide", type=Path, help="Fresh /api/integration-guide response")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()

    if bool(args.openapi) != bool(args.guide):
        parser.error("--openapi and --guide must be supplied together")

    actual = extract(load(args.openapi), load(args.guide)) if args.openapi else load(args.fixture)
    errors = validate(actual)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    if args.refresh:
        if not args.openapi:
            parser.error("--refresh requires --openapi and --guide")
        args.fixture.parent.mkdir(parents=True, exist_ok=True)
        args.fixture.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"refreshed {args.fixture}")
        return 0

    if args.openapi:
        fixture = load(args.fixture)
        if actual != fixture:
            print("ERROR: live contract sources differ from the grounded fixture; review and refresh")
            return 1
    print("contract sources validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
