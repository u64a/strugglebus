from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from contract_sources import load, validate  # noqa: E402


class ContractSourceTest(unittest.TestCase):
    def test_grounded_fixture_matches_required_shapes_and_limits(self) -> None:
        fixture = load(ROOT / "fixtures" / "strugglebus-contract-source.json")
        self.assertEqual([], validate(fixture))
        self.assertEqual("1.14.0", fixture["guide_version"])
        self.assertIn("MobileWriteGrantRequest", fixture["schemas"])
        self.assertIn("MobileConfirmationResponse", fixture["schemas"])
        self.assertIn("MobileActionRequest", fixture["schemas"])

    def test_deployed_mobile_behaviors_are_grounded(self) -> None:
        provenance = json.loads(
            (ROOT / "contract-provenance.json").read_text(encoding="utf-8")
        )
        by_id = {item["id"]: item for item in provenance["behaviors"]}
        grounded_behaviors = {
            "mobile-reads-during-freeze",
            "mobile-principal-separation",
            "mobile-channel-visibility",
            "mobile-write-grant",
            "mobile-confirmation-binding",
            "mobile-actions-during-freeze",
        }
        self.assertTrue(grounded_behaviors.issubset(by_id))
        for behavior_id in grounded_behaviors:
            self.assertIn("source-read", by_id[behavior_id]["provenance"])
            self.assertNotIn("assumed", by_id[behavior_id]["provenance"])

    def test_replay_claim_is_source_read_not_document_inferred(self) -> None:
        provenance = json.loads(
            (ROOT / "contract-provenance.json").read_text(encoding="utf-8")
        )
        replay = next(
            item
            for item in provenance["behaviors"]
            if item["id"] == "enrollment-replay-impossible"
        )
        self.assertIn("source-read", replay["provenance"])
        self.assertNotIn("assumed", replay["provenance"])


if __name__ == "__main__":
    unittest.main()
