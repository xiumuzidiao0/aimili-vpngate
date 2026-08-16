import base64
import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import singbox_manager
import vpngate_manager


class SingBoxManagerTests(unittest.TestCase):
    def test_new_proxy_chain_defaults_to_host_network(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({
            "private_key": "private-key",
            "public_key": "public-key",
            "public_host": "vpn.example.com",
        })
        normalized = singbox_manager.normalize_settings(settings, 7928, {8787, 7928})
        config = singbox_manager.build_proxy_chain_config(normalized)

        self.assertEqual(config["route"]["final"], "direct")
        self.assertEqual(config["outbounds"][0]["type"], "direct")
        self.assertNotIn("server", config["outbounds"][0])

    def test_proxy_chain_forces_local_http_port(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({"private_key": "private-key", "public_key": "public-key"})
        settings["vpn_exit_id"] = "default"

        # Obsolete upstream settings must not be able to redirect egress.
        settings["upstream_host"] = "198.51.100.8"
        normalized = singbox_manager.normalize_settings(settings, 7928, {8787, 7928})
        self.assertEqual(normalized["local_http_port"], 7928)

        settings["port"] = 8787
        with self.assertRaises(singbox_manager.SingBoxError):
            singbox_manager.normalize_settings(settings, 7928, {8787, 7928})

    def test_proxy_chain_allows_only_registered_vpn_exit_ports(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({
            "private_key": "private-key",
            "public_key": "public-key",
            "local_http_port": 7929,
            "vpn_exit_id": "japan",
        })

        normalized = singbox_manager.normalize_settings(
            settings, 7928, {8787, 7928}, {7928, 7929},
        )
        self.assertEqual(normalized["local_http_port"], 7929)
        self.assertEqual(normalized["vpn_exit_id"], "japan")

        settings["local_http_port"] = 18080
        with self.assertRaises(singbox_manager.SingBoxError):
            singbox_manager.normalize_settings(settings, 7928, {8787, 7928}, {7928, 7929})

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
                self.assertEqual(saved["local_http_port"], 7928)
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

    def test_client_uri_uses_each_node_name_host_and_port(self):
        first = singbox_manager.default_settings(7928)
        first.update({
            "name": "日本入口 A",
            "protocol": "vless",
            "public_host": "vpn.example.com",
            "port": 18443,
        })
        second = {**first, "name": "日本入口 B", "port": 28443}

        first_uri = singbox_manager.client_info(first)["uri"]
        second_uri = singbox_manager.client_info(second)["uri"]
        first_parts = urllib.parse.urlsplit(first_uri)
        second_parts = urllib.parse.urlsplit(second_uri)

        self.assertEqual(first_parts.hostname, "vpn.example.com")
        self.assertEqual(first_parts.port, 18443)
        self.assertEqual(second_parts.port, 28443)
        self.assertEqual(urllib.parse.unquote(first_parts.fragment), "日本入口 A")
        self.assertEqual(urllib.parse.unquote(second_parts.fragment), "日本入口 B")
        self.assertNotEqual(first_uri, second_uri)

    def test_client_uri_formats_ipv6_and_reserved_credentials(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({
            "name": "IPv6 HTTP",
            "protocol": "http",
            "public_host": "[2001:db8::8]",
            "port": 18080,
            "username": "user@example.com",
            "password": "p@ss:/?#",
        })
        info = singbox_manager.client_info(settings)
        parts = urllib.parse.urlsplit(info["uri"])

        self.assertEqual(info["endpoint"], "[2001:db8::8]:18080")
        self.assertEqual(parts.hostname, "2001:db8::8")
        self.assertEqual(parts.port, 18080)
        self.assertEqual(urllib.parse.unquote(parts.username), "user@example.com")
        self.assertEqual(urllib.parse.unquote(parts.password), "p@ss:/?#")
        self.assertEqual(urllib.parse.unquote(parts.fragment), "IPv6 HTTP")

    def test_vmess_client_uri_embeds_custom_node_name(self):
        settings = singbox_manager.default_settings(7928)
        settings.update({
            "name": "自定义 VMess 节点",
            "protocol": "vmess",
            "public_host": "203.0.113.8",
            "port": 34567,
        })
        encoded = singbox_manager.client_info(settings)["uri"].removeprefix("vmess://")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

        self.assertEqual(payload["ps"], "自定义 VMess 节点")
        self.assertEqual(payload["add"], "203.0.113.8")
        self.assertEqual(payload["port"], "34567")

    def test_supported_protocols_build_a_vpngate_chain(self):
        for protocol in sorted(singbox_manager.SUPPORTED_PROTOCOLS):
            settings = singbox_manager.default_settings(7928)
            settings["protocol"] = protocol
            settings["port"] = 4500
            settings["vpn_exit_id"] = "default"
            if protocol == "vless-reality":
                settings.update({"private_key": "private-key", "public_key": "public-key"})
            normalized = singbox_manager.normalize_settings(settings, 7928, {8787, 7928})
            config = singbox_manager.build_proxy_chain_config(normalized)
            self.assertEqual(config["route"]["final"], "vpngate-chain")
            self.assertEqual(config["outbounds"][0]["type"], "http")
            self.assertEqual(config["outbounds"][0]["server_port"], 7928)
            self.assertEqual(config["inbounds"][0]["type"], "vless" if protocol == "vless-reality" else protocol)

    def test_multiple_protocol_nodes_share_the_http_vpngate_chain(self):
        nodes = []
        for index, protocol in enumerate(("vless", "shadowsocks", "tuic")):
            node = singbox_manager.new_node(7928, protocol)
            node["port"] = 4500 + index
            node["vpn_exit_id"] = "default"
            nodes.append(node)

        normalized = singbox_manager.normalize_nodes(nodes, 7928, {8787, 7928})
        config = singbox_manager.build_proxy_chain_nodes(normalized)

        self.assertEqual(len(config["inbounds"]), 3)
        self.assertEqual(config["outbounds"][0]["type"], "http")
        self.assertEqual(config["outbounds"][0]["server_port"], 7928)
        self.assertEqual(config["route"]["final"], "block")
        self.assertEqual(len(config["route"]["rules"]), 3)

    def test_multiple_vpn_exits_get_separate_outbounds(self):
        first = singbox_manager.new_node(7928, "vless")
        first.update({"id": "default-node", "name": "主机直连", "port": 4500, "vpn_exit_id": "default"})
        second = singbox_manager.new_node(7928, "shadowsocks")
        second.update({"id": "japan-node", "port": 4501, "local_http_port": 7929, "vpn_exit_id": "japan"})

        normalized = singbox_manager.normalize_nodes(
            [first, second], 7928, {8787, 7928}, {7928, 7929},
        )
        self.assertEqual(normalized[0]["name"], "主机直连")
        config = singbox_manager.build_proxy_chain_nodes(normalized)
        http_outbounds = [item for item in config["outbounds"] if item["type"] == "http"]
        self.assertEqual({item["server_port"] for item in http_outbounds}, {7928, 7929})
        self.assertEqual(
            {rule["outbound"] for rule in config["route"]["rules"]},
            {"vpngate-chain-7928", "vpngate-chain-7929"},
        )

    def test_openrc_reload_maps_to_restart(self):
        with patch.object(singbox_manager, "_service_manager", return_value="openrc"), \
             patch.object(singbox_manager, "_run") as run, \
             patch.object(singbox_manager.time, "sleep"), \
             patch.object(singbox_manager, "status", return_value={"running": True}):
            run.return_value.returncode = 0
            singbox_manager.service_action("reload")
            run.assert_called_once_with(["rc-service", "sing-box", "restart"], timeout=30)


class VpnExitTests(unittest.TestCase):
    def test_normalize_exits_and_bind_singbox_nodes(self):
        ui_config = {"proxy_port": 7928, "port": 8787, "singbox": {"nodes": []}}
        raw_exits = [
            {"id": "default", "name": "ignored", "node_id": "japan", "proxy_port": 9999, "country": "日本", "ip_type": "residential"},
            {"id": "usa", "name": "美国出口", "node_id": "us-node", "proxy_port": 7929, "country": "美国", "ip_type": "hosting", "enabled": True},
        ]
        with patch.object(vpngate_manager, "read_nodes", return_value=[{"id": "japan"}, {"id": "us-node"}]):
            exits = vpngate_manager.normalize_vpn_exits(raw_exits, ui_config)

        self.assertEqual(exits[0]["proxy_port"], 7928)
        self.assertEqual(exits[0]["name"], "默认出口")
        self.assertEqual(exits[0]["ip_type"], "residential")
        self.assertEqual(exits[1]["proxy_port"], 7929)
        self.assertEqual(exits[1]["country"], "美国")
        bound = vpngate_manager.bind_singbox_nodes_to_vpn_exits(
            [{"id": "client-us", "vpn_exit_id": "usa"}],
            vpngate_manager.current_vpn_exits({**ui_config, "vpn_exits": exits}),
        )
        self.assertEqual(bound[0]["local_http_port"], 7929)

    def test_bind_rejects_unknown_exit(self):
        with self.assertRaises(singbox_manager.SingBoxError):
            vpngate_manager.bind_singbox_nodes_to_vpn_exits(
                [{"id": "client", "vpn_exit_id": "missing"}],
                [{"id": "default", "proxy_port": 7928}],
            )

    def test_bind_allows_direct_without_vpngate_exit(self):
        bound = vpngate_manager.bind_singbox_nodes_to_vpn_exits(
            [{"id": "client", "vpn_exit_id": "direct", "local_http_port": 7928}],
            [],
        )
        self.assertEqual(bound[0]["vpn_exit_id"], "direct")

    def test_service_action_reports_immediate_exit(self):
        with patch.object(singbox_manager, "_service_manager", return_value="openrc"), \
             patch.object(singbox_manager, "_run") as run, \
             patch.object(singbox_manager.time, "sleep"), \
             patch.object(singbox_manager, "status", return_value={"running": False, "service_detail": "crashed"}), \
             patch.object(singbox_manager, "recent_logs", return_value=["bind: address already in use"]):
            run.return_value.returncode = 0
            with self.assertRaisesRegex(singbox_manager.SingBoxError, "address already in use"):
                singbox_manager.service_action("restart")


if __name__ == "__main__":
    unittest.main()
