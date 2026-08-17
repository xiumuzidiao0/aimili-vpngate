import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch

import vpngate_manager


class WebUiContractTests(unittest.TestCase):
    def test_primary_workspaces_have_stable_routes(self):
        html = vpngate_manager.INDEX_HTML

        for view in ("overview", "singbox", "vpn-exits", "combinations"):
            self.assertIn(f'data-view-target="{view}"', html)
        self.assertIn("primaryViewFromLocation", html)
        self.assertIn("#/", html)

    def test_client_links_are_masked_and_qr_stays_same_origin(self):
        html = vpngate_manager.INDEX_HTML

        self.assertIn('id="sb_client_uri" class="input-field mono" type="password"', html)
        self.assertIn("./api/singbox/qr?node_id=", html)
        self.assertNotIn("api.qrserver.com", html)
        self.assertNotIn("chart.googleapis.com", html)

    def test_management_workflows_expose_batch_and_preview_controls(self):
        html = vpngate_manager.INDEX_HTML

        self.assertIn("exportSingboxLinks('text')", html)
        self.assertIn("exportSingboxLinks('json')", html)
        self.assertIn("applyCombinationBatch()", html)
        self.assertIn("previewSingboxCombinations()", html)
        self.assertIn('id="ve_available_only"', html)
        self.assertIn('id="ve_max_ping"', html)
        self.assertIn('id="ve_min_speed"', html)
        self.assertIn("自动切换（按国家和 IP 类型）", html)

    def test_mobile_node_list_uses_object_cards(self):
        html = vpngate_manager.INDEX_HTML

        self.assertIn(".table-container thead { display: none; }", html)
        for label in ("状态", "节点地址", "物理位置", "运营主体", "IP 类型", "操作"):
            self.assertIn(f'data-label="{label}"', html)

    def test_installer_includes_local_qr_encoder(self):
        installer = Path(__file__).resolve().parents[1].joinpath("install.sh").read_text(encoding="utf-8")

        self.assertIn("apt-get install -y qrencode ||", installer)
        self.assertIn("apk add libqrencode-tools ||", installer)
        self.assertIn("$PKG_MGR install -y qrencode ||", installer)
        self.assertGreaterEqual(installer.count("其余功能不受影响"), 3)

    def test_readme_installer_does_not_execute_http_error_pages(self):
        readme = Path(__file__).resolve().parents[1].joinpath("README.md").read_text(encoding="utf-8")

        self.assertNotIn("bash <(curl -Ls https://raw.githubusercontent.com", readme)
        self.assertGreaterEqual(readme.count("https://cdn.jsdelivr.net/gh/xiumuzidiao0/aimili-vpngate@main/install.sh"), 2)
        self.assertGreaterEqual(readme.count("curl -LfsS"), 2)
        self.assertGreaterEqual(readme.count("grep -q '^#!/usr/bin/env bash'"), 2)

    def test_qr_generation_passes_credentials_over_stdin(self):
        node = vpngate_manager.singbox_manager.default_settings(7928)
        node.update({
            "id": "node1",
            "name": "测试节点",
            "public_host": "vpn.example.com",
            "public_key": "public-key",
            "private_key": "private-key",
        })
        png = b"\x89PNG\r\n\x1a\nmock"
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=png, stderr=b"")

        with patch("vpngate_manager.subprocess.run", return_value=completed) as run:
            self.assertEqual(vpngate_manager.singbox_qr_png(node), png)

        args, kwargs = run.call_args
        self.assertNotIn("vless://", " ".join(args[0]))
        self.assertIn(b"vless://", kwargs["input"])

    def test_qr_generation_rejects_non_png_output(self):
        node = vpngate_manager.singbox_manager.default_settings(7928)
        node.update({"public_host": "vpn.example.com", "public_key": "public-key", "private_key": "private-key"})
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"not-png", stderr=b"")

        with patch("vpngate_manager.subprocess.run", return_value=completed):
            with self.assertRaises(vpngate_manager.singbox_manager.SingBoxError):
                vpngate_manager.singbox_qr_png(node)


if __name__ == "__main__":
    unittest.main()
