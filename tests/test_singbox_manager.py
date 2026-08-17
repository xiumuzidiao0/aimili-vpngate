import base64
import json
import os
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

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

    def test_all_disabled_nodes_produce_a_valid_block_only_config(self):
        node = singbox_manager.new_node(7928, "vless")
        node["enabled"] = False
        node["chain_enabled"] = False
        normalized = singbox_manager.normalize_nodes([node], 7928, {8787, 7928})

        config = singbox_manager.build_proxy_chain_nodes(normalized)

        self.assertEqual(config["inbounds"], [])
        self.assertEqual(config["route"]["rules"], [])
        self.assertEqual(config["route"]["final"], "block")
        self.assertEqual(config["outbounds"], [{"type": "block", "tag": "block"}])

    def test_real_singbox_check_for_generated_chain_when_binary_is_configured(self):
        binary = os.environ.get("SINGBOX_TEST_BIN")
        if not binary or not os.path.isfile(binary):
            self.skipTest("set SINGBOX_TEST_BIN to run the real sing-box integration check")
        node = singbox_manager.new_node(7928, "vless")
        node.update({"port": 4500, "vpn_exit_id": "direct", "enabled": True, "chain_enabled": True})
        normalized = singbox_manager.normalize_nodes([node], 7928, {8787, 7928})
        config = singbox_manager.build_proxy_chain_nodes(normalized)
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory) / "config.json"
            config_file.write_text(json.dumps(config), encoding="utf-8")
            result = subprocess.run([binary, "check", "-c", str(config_file)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

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
        self.assertEqual(exits[1]["tun_name"], "tun1")
        self.assertEqual(exits[1]["route_table"], 101)
        self.assertEqual(exits[1]["country"], "美国")
        bound = vpngate_manager.bind_singbox_nodes_to_vpn_exits(
            [{"id": "client-us", "vpn_exit_id": "usa"}],
            vpngate_manager.current_vpn_exits({**ui_config, "vpn_exits": exits}),
        )
        self.assertEqual(bound[0]["local_http_port"], 7929)

    def test_vpn_exit_tun_and_route_assignment_survives_reordering(self):
        ui_config = {
            "proxy_port": 7928,
            "port": 8787,
            "singbox": {"nodes": []},
            "vpn_exits": [
                {"id": "default", "proxy_port": 7928, "tun_name": "tun0", "route_table": 100},
                {"id": "usa", "proxy_port": 7929, "tun_name": "tun1", "route_table": 101},
                {"id": "japan", "proxy_port": 7930, "tun_name": "tun2", "route_table": 102},
            ],
        }
        reordered = [
            {"id": "default", "node_id": "", "proxy_port": 7928},
            {"id": "japan", "node_id": "", "proxy_port": 7930},
            {"id": "usa", "node_id": "", "proxy_port": 7929},
        ]

        with patch.object(vpngate_manager, "read_nodes", return_value=[]):
            normalized = vpngate_manager.normalize_vpn_exits(reordered, ui_config)

        by_id = {item["id"]: item for item in normalized}
        self.assertEqual((by_id["usa"]["tun_name"], by_id["usa"]["route_table"]), ("tun1", 101))
        self.assertEqual((by_id["japan"]["tun_name"], by_id["japan"]["route_table"]), ("tun2", 102))

    def test_vpn_exit_start_failure_cleans_process_route_and_proxy(self):
        exit_config = {
            "id": "usa",
            "enabled": True,
            "node_id": "us-node",
            "tun_name": "tun1",
            "route_table": 101,
            "proxy_port": 7929,
        }
        process = MagicMock(pid=1234)
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(vpngate_manager, "CONFIG_DIR", Path(directory)), \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=[exit_config]), \
             patch.object(vpngate_manager, "read_nodes", return_value=[{"id": "us-node", "config_text": "client"}]), \
             patch.object(vpngate_manager, "run_openvpn_until_ready", return_value=(True, "ready", process)), \
             patch.object(vpngate_manager, "setup_policy_routing", side_effect=RuntimeError("route failed")), \
             patch.object(vpngate_manager, "stop_process") as stop_process, \
             patch.object(vpngate_manager, "cleanup_policy_routing") as cleanup_route, \
             patch.object(vpngate_manager, "stop_vpn_exit_proxy") as stop_proxy:
            vpngate_manager.vpn_exit_processes.clear()
            vpngate_manager.vpn_exit_runtime_states.clear()
            with self.assertRaisesRegex(RuntimeError, "route failed"):
                vpngate_manager.start_vpn_exit("usa")

        stop_process.assert_called_once_with(process)
        cleanup_route.assert_called_once_with(101)
        stop_proxy.assert_called_once_with("usa", 7929)
        self.assertNotIn("usa", vpngate_manager.vpn_exit_processes)
        self.assertEqual(vpngate_manager.vpn_exit_runtime_states["usa"]["phase"], "failed")

    def test_vpn_exit_start_reports_proxy_ready_phase(self):
        exit_config = {
            "id": "usa",
            "enabled": True,
            "node_id": "us-node",
            "tun_name": "tun1",
            "route_table": 101,
            "proxy_port": 7929,
        }
        process = MagicMock(pid=1234)
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(vpngate_manager, "CONFIG_DIR", Path(directory)), \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=[exit_config]), \
             patch.object(vpngate_manager, "read_nodes", return_value=[{"id": "us-node", "config_text": "client"}]), \
             patch.object(vpngate_manager, "run_openvpn_until_ready", return_value=(True, "ready", process)), \
             patch.object(vpngate_manager, "setup_policy_routing"), \
             patch.object(vpngate_manager, "start_vpn_exit_proxy"), \
             patch.object(vpngate_manager, "wait_for_tcp_listener", return_value=True):
            vpngate_manager.vpn_exit_processes.clear()
            vpngate_manager.vpn_exit_runtime_states.clear()
            status = vpngate_manager.start_vpn_exit("usa")

        self.assertTrue(status["running"])
        self.assertEqual(status["phase"], "proxy_ready")
        self.assertEqual(status["runtime"]["proxy_endpoint"], "127.0.0.1:7929")
        vpngate_manager.vpn_exit_processes.clear()

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
