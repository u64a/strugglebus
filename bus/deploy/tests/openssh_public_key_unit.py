"""Offline tests for the OpenSSH public key filter."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "filter_plugins"
    / "openssh_public_key.py"
)
SPEC = importlib.util.spec_from_file_location("openssh_public_key", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the OpenSSH public key filter module")
openssh_public_key = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(openssh_public_key)


class PublicKeyTests(unittest.TestCase):
    def test_public_key_wire_format_validation(self) -> None:
        valid_key = (
            "ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAICIuHNI9KeMG2RRI/"
            "61BDRGGH/QSZD8WT8kxZlntrSES operator laptop key"
        )
        errors = openssh_public_key.public_key_errors
        self.assertEqual(errors(valid_key), [])
        self.assertTrue(errors("ssh-ed25519 QUFBQQ== incomplete"))
        self.assertTrue(errors("ssh-dss AAAAB3NzaC1kc3M="))
        self.assertTrue(errors(None))


if __name__ == "__main__":
    unittest.main()
