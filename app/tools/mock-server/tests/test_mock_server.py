from __future__ import annotations

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mock_server import MobileMockServer  # noqa: E402


class MockServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = MobileMockServer(
            ("127.0.0.1", 0),
            public_endpoint="https://10.0.2.2:8443",
            ca_sha256="00" * 32,
            stream_seconds=0.05,
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        state_type = type(self.server.state)
        self.server.state = state_type()
        self.mobile_credential = self._enroll()

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict | None = None,
        bearer: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict, bytes]:
        data = None if body is None else json.dumps(body).encode()
        request_headers = dict(headers or {})
        if bearer:
            request_headers["Authorization"] = f"Bearer {bearer}"
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers=request_headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()

    def _enroll(self, request_id: str | None = None) -> str:
        body = {"request_id": request_id or str(uuid4())}
        status, headers, raw = self.request(
            "/api/mobile/enrollments/redeem",
            method="POST",
            body=body,
            bearer=self.server.state.enrollment_token,
        )
        self.assertEqual(201, status)
        self.assertEqual("no-store", headers.get("Cache-Control"))
        payload = json.loads(raw)
        self.assertEqual("Test phone", payload["device_label"])
        return payload["credential_secret"]

    def test_enrollment_is_single_use_and_never_replayable(self) -> None:
        # Production verifies the token before any request-id lookup and stores only a
        # one-way hash of the secret, so replay is impossible rather than merely absent.
        request_id = str(uuid4())
        status, _, _ = self.request(
            "/api/mobile/enrollments/redeem",
            method="POST",
            body={"request_id": request_id},
            bearer=self.server.state.enrollment_token,
        )
        self.assertEqual(401, status)

    def test_replaying_a_successful_request_id_is_still_refused(self) -> None:
        self.server.state = type(self.server.state)()
        request_id = str(uuid4())
        credential = self._enroll(request_id)
        self.assertTrue(credential.startswith("sbm1_"))
        status, headers, raw = self.request(
            "/api/mobile/enrollments/redeem",
            method="POST",
            body={"request_id": request_id},
            bearer=self.server.state.enrollment_token,
        )
        self.assertEqual(401, status)
        self.assertEqual("Bearer", headers.get("WWW-Authenticate"))
        self.assertNotIn("credential", json.loads(raw))

    def _grant(self) -> tuple[str, str]:
        status, headers, raw = self.request(
            "/api/mobile/grants",
            method="POST",
            bearer=self.mobile_credential,
            body={
                "request_id": str(uuid4()),
                "operator_password": "correct horse battery staple",
                "reason": "Configure protected test operator access",
            },
        )
        self.assertEqual(201, status)
        self.assertEqual("no-store", headers.get("Cache-Control"))
        payload = json.loads(raw)
        return payload["grant_secret"], payload["device_id"]

    def _confirmation(self, action: str, target_id: str) -> dict:
        status, _, raw = self.request(
            "/api/mobile/confirmations",
            method="POST",
            bearer=self.mobile_credential,
            body={"request_id": str(uuid4()), "action": action, "target_id": target_id},
        )
        self.assertEqual(201, status)
        return json.loads(raw)

    def _action(self, confirmation: dict, grant: str, *, action: str | None = None) -> tuple[int, dict]:
        status, _, raw = self.request(
            "/api/mobile/actions",
            method="POST",
            bearer=self.mobile_credential,
            body={
                "request_id": str(uuid4()),
                "confirmation_id": confirmation["confirmation_id"],
                "action": action or confirmation["action"],
                "target_id": confirmation["target_id"],
                "grant_secret": grant,
                "reason": "Contain compromised test principal",
            },
        )
        return status, json.loads(raw)

    def test_mobile_write_grant_is_per_device_and_replaced(self) -> None:
        first, device_id = self._grant()
        second, replacement_device_id = self._grant()
        self.assertEqual(device_id, replacement_device_id)
        confirmation = self._confirmation("activate-freeze", "global")
        status, _ = self._action(confirmation, first)
        self.assertEqual(401, status)
        replacement_confirmation = self._confirmation("activate-freeze", "global")
        status, payload = self._action(replacement_confirmation, second)
        self.assertEqual(200, status)
        self.assertTrue(payload["applied"])

    def test_grant_creation_is_blocked_while_frozen(self) -> None:
        self.request("/__control/state", method="POST", body={"frozen": True})
        status, _, raw = self.request(
            "/api/mobile/grants",
            method="POST",
            bearer=self.mobile_credential,
            body={
                "request_id": str(uuid4()),
                "operator_password": "correct horse battery staple",
                "reason": "Configure protected test operator access",
            },
        )
        self.assertEqual(503, status)
        self.assertEqual("agent access is frozen", json.loads(raw)["detail"])

    def test_confirmation_binding_rejects_action_mismatch(self) -> None:
        grant, _ = self._grant()
        confirmation = self._confirmation("activate-freeze", "global")
        status, _ = self._action(confirmation, grant, action="clear-freeze")
        self.assertEqual(409, status)
        self.assertFalse(self.server.state.frozen)

    def test_existing_grant_can_clear_freeze(self) -> None:
        grant, _ = self._grant()
        self.request("/__control/state", method="POST", body={"frozen": True})
        confirmation = self._confirmation("clear-freeze", "global")
        status, payload = self._action(confirmation, grant)
        self.assertEqual(200, status)
        self.assertTrue(payload["applied"])
        self.assertFalse(self.server.state.frozen)

    def test_block_agent_and_revoke_device(self) -> None:
        grant, device_id = self._grant()
        block = self._confirmation("block-agent", "agent-example")
        status, _ = self._action(block, grant)
        self.assertEqual(200, status)
        self.assertIn("agent-example", self.server.state.blocked_agents)

        revoke = self._confirmation("revoke-device", device_id)
        status, _ = self._action(revoke, grant)
        self.assertEqual(200, status)
        status, _, _ = self.request("/api/mobile/status", bearer=self.mobile_credential)
        self.assertEqual(401, status)

    def test_operator_log_view(self) -> None:
        status, _, raw = self.request("/api/mobile/admin/logs?limit=2", bearer=self.mobile_credential)
        self.assertEqual(200, status)
        log = json.loads(raw)
        self.assertEqual("0.2.65", log["version"])
        self.assertEqual(["request", "audit"], [entry["source"] for entry in log["entries"]])
        self.assertEqual(401, log["entries"][0]["status"])
        status, _, _ = self.request("/api/mobile/admin/logs?limit=501", bearer=self.mobile_credential)
        self.assertEqual(422, status)
        status, _, _ = self.request("/api/mobile/admin/logs")
        self.assertEqual(401, status)

    def test_management_lists_and_controls(self) -> None:
        grant, device_id = self._grant()
        status, _, raw = self.request("/api/mobile/admin/agents?state=all", bearer=self.mobile_credential)
        self.assertEqual(200, status)
        agents = {row["name"]: row for row in json.loads(raw)}
        self.assertEqual(["unblock", "retire"], [o["action"] for o in agents["maintainer-agent"]["actions"]])
        self.assertEqual([], agents["old-runner"]["actions"])

        status, _, raw = self.request("/api/mobile/admin/devices", bearer=self.mobile_credential)
        devices = json.loads(raw)
        self.assertEqual(device_id, devices[0]["id"])
        self.assertTrue(devices[0]["this_device"] and devices[0]["has_write_grant"])

        target = agents["maintainer-agent"]
        body = {
            "request_id": str(uuid4()), "action": "unblock", "expected_name": target["name"],
            "expected_credential_epoch": target["credential_epoch"], "reason": "test", "grant_secret": grant,
        }
        path = f"/api/mobile/admin/agents/{target['id']}/control"
        status, _, _ = self.request(path, method="POST", bearer=self.mobile_credential, body={**body, "grant_secret": "wrong"})
        self.assertEqual(401, status)
        status, _, raw = self.request(path, method="POST", bearer=self.mobile_credential, body=body)
        self.assertEqual(200, status)
        self.assertEqual("enabled", json.loads(raw)["state"])
        status, _, _ = self.request(path, method="POST", bearer=self.mobile_credential, body=body)
        self.assertEqual(409, status)  # the listed epoch is stale now

        status, _, raw = self.request("/api/mobile/admin/service-principals", bearer=self.mobile_credential)
        principal = json.loads(raw)[0]
        status, _, raw = self.request(
            f"/api/mobile/admin/service-principals/{principal['id']}/control", method="POST",
            bearer=self.mobile_credential,
            body={
                "request_id": str(uuid4()), "action": "rotate", "expected_name": principal["name"],
                "expected_version": principal["version"], "reason": "test", "grant_secret": grant,
            },
        )
        self.assertEqual(200, status)
        self.assertEqual("service-principal-credential", json.loads(raw)["secret_kind"])
        self.assertTrue(json.loads(raw)["secret"])

    def test_snapshot_is_non_consuming(self) -> None:
        before = list(self.server.state.messages)
        for _ in range(2):
            status, _, raw = self.request(
                "/api/mobile/snapshot?limit=1", bearer=self.mobile_credential
            )
            payload = json.loads(raw)
            self.assertEqual(200, status)
            self.assertIsInstance(payload, list)
            self.assertEqual(1, len(payload))
        self.assertEqual(before, self.server.state.messages)

    def test_freeze_keeps_monitor_reads_available(self) -> None:
        self.request("/__control/state", method="POST", body={"frozen": True})
        status, _, raw = self.request("/api/mobile/status", bearer=self.mobile_credential)
        self.assertEqual(200, status)
        self.assertEqual(
            {"api_version", "server_time", "state"}, set(json.loads(raw).keys())
        )
        self.assertEqual("frozen", json.loads(raw)["state"])
        for path in (
            "/api/mobile/snapshot",
            "/api/mobile/channels",
            "/api/mobile/agents",
            "/api/mobile/stream?since=0",
        ):
            status, _, _ = self.request(path, bearer=self.mobile_credential)
            self.assertEqual(200, status, path)

    def test_revocation_blocks_new_requests(self) -> None:
        self.request("/__control/state", method="POST", body={"revoked": True})
        status, headers, _ = self.request(
            "/api/mobile/snapshot", bearer=self.mobile_credential
        )
        self.assertEqual(401, status)
        self.assertEqual("no-store", headers.get("Cache-Control"))
        self.assertEqual("Bearer", headers.get("WWW-Authenticate"))

    def test_authentication_activity_writes_are_coalesced(self) -> None:
        before = self.server.state.authentication_writes
        self.request("/api/mobile/snapshot", bearer=self.mobile_credential)
        self.request("/api/mobile/channels", bearer=self.mobile_credential)
        self.assertEqual(before + 1, self.server.state.authentication_writes)
        self.assertIsNotNone(self.server.state.last_used_at)

    def test_control_diagnostics_exposes_only_test_counters(self) -> None:
        status, headers, raw = self.request("/__control/diagnostics")
        self.assertEqual(200, status)
        self.assertEqual("no-store", headers.get("Cache-Control"))
        self.assertEqual(
            {"active_streams", "authentication_writes"},
            set(json.loads(raw)),
        )

    def test_terminal_event_has_no_id_and_heartbeat_is_comment(self) -> None:
        self.request(
            "/__control/state",
            method="POST",
            body={"terminal_event": "agent_access_unavailable"},
        )
        status, _, raw = self.request(
            "/api/mobile/stream?since=2", bearer=self.mobile_credential
        )
        text = raw.decode()
        self.assertEqual(200, status)
        self.assertIn("event: agent_access_unavailable\n", text)
        self.assertNotIn("id:", text)

    def test_fourth_stream_is_rejected_with_retry_after(self) -> None:
        self.server.state.active_streams = 3
        status, headers, _ = self.request(
            "/api/mobile/stream", bearer=self.mobile_credential
        )
        self.assertEqual(429, status)
        self.assertEqual("1", headers.get("Retry-After"))

    def test_freeze_does_not_truncate_a_monitor_batch(self) -> None:
        self.request(
            "/__control/state",
            method="POST",
            body={"freeze_after_sequence": 1},
        )
        status, _, raw = self.request(
            "/api/mobile/stream?since=0", bearer=self.mobile_credential
        )
        text = raw.decode()
        self.assertEqual(200, status)
        self.assertIn("id: 1\n", text)
        self.assertIn("id: 2\n", text)
        self.assertNotIn("event: agent_access_frozen\n", text)

    def test_stream_resumes_after_greater_cursor(self) -> None:
        status, _, raw = self.request(
            "/api/mobile/stream?since=1",
            bearer=self.mobile_credential,
            headers={"Last-Event-ID": "0"},
        )
        text = raw.decode()
        self.assertEqual(200, status)
        self.assertNotIn("id: 1\n", text)
        self.assertIn("id: 2\n", text)
        self.assertIn("event: message\n", text)
        self.assertIn(": heartbeat\n\n", text)


if __name__ == "__main__":
    unittest.main()
