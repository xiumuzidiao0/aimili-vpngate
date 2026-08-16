import tempfile
import unittest
from pathlib import Path

import singbox_manager


class SingBoxManagerTests(unittest.TestCase):
    def test_proxy_chain_never_has_direct_fallback(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({
            "private_key": "private-key",
            "public_key": "public-key",
            "public_host": "vpn.example.com",
        })
        normalized = singbox_manager.normalize_settings(settings, 7928, {8787, 7928})
        config = singbox_manager.build_proxy_chain_config(normalized)

        self.assertEqual(config["route"]["final"], "vpngate-chain")
        self.assertEqual(config["outbounds"][0]["type"], "socks")
        self.assertEqual(config["outbounds"][0]["server"], "127.0.0.1")
        self.assertEqual(config["outbounds"][0]["server_port"], 7928)
        self.assertNotIn("direct", [item["type"] for item in config["outbounds"]])

    def test_proxy_chain_rejects_non_local_or_conflicting_ports(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({"private_key": "private-key", "public_key": "public-key"})

        settings["upstream_host"] = "198.51.100.8"
        with self.assertRaises(singbox_manager.SingBoxError):
            singbox_manager.normalize_settings(settings, 7928, {8787, 7928})

        settings["upstream_host"] = "127.0.0.1"
        settings["port"] = 8787
        with self.assertRaises(singbox_manager.SingBoxError):
            singbox_manager.normalize_settings(settings, 7928, {8787, 7928})

    def test_save_config_uses_validated_atomic_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "sing-box"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            config_path = root / "config.json"

            old_bin = singbox_manager.SINGBOX_BIN
            old_config = singbox_manager.SINGBOX_CONFIG
            singbox_manager.SINGBOX_BIN = binary
            singbox_manager.SINGBOX_CONFIG = config_path
            try:
                settings = singbox_manager.default_settings(7928)
                settings.update({"private_key": "private-key", "public_key": "public-key"})
                saved = singbox_manager.save_config(settings, 7928, {8787, 7928})
                self.assertTrue(config_path.exists())
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(saved["upstream_port"], 7928)
            finally:
                singbox_manager.SINGBOX_BIN = old_bin
                singbox_manager.SINGBOX_CONFIG = old_config

    def test_client_uri_requires_host_and_public_key(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({"private_key": "private-key", "public_key": "public-key"})
        with self.assertRaises(singbox_manager.SingBoxError):
            singbox_manager.client_info(settings)

        settings["public_host"] = "vpn.example.com"
        uri = singbox_manager.client_info(settings)["uri"]
        self.assertTrue(uri.startswith("vless://"))
        self.assertIn("security=reality", uri)
        self.assertIn("pbk=public-key", uri)


if __name__ == "__main__":
    unittest.main()
