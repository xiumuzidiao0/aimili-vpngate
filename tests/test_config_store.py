import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config_store
import auth_security
import singbox_manager
import vpngate_manager


class ConfigStoreTests(unittest.TestCase):
    def test_atomic_write_uses_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.json"
            config_store.atomic_write_json(target, {"name": "节点"})

            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"name": "节点"})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(target.parent.glob("*.tmp")), [])

    def test_migrate_v1_adds_desired_state(self):
        migrated, changed = config_store.migrate_ui_config(
            {
                "singbox": {"enabled": True, "chain_enabled": True},
                "vpn_exits": [
                    {"id": "default", "enabled": True},
                    {"id": "usa", "enabled": True},
                ],
            },
            now=123,
        )

        self.assertTrue(changed)
        self.assertEqual(migrated["schema_version"], 2)
        self.assertEqual(migrated["migrated_from"], 1)
        self.assertEqual(migrated["migrated_at"], 123)
        self.assertEqual(migrated["desired_state"]["singbox"], "running")
        self.assertEqual(
            migrated["desired_state"]["vpn_exits"],
            {"default": "running", "usa": "stopped"},
        )

    def test_save_versioned_config_keeps_restorable_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ui_auth.json"
            config_store.atomic_write_json(target, {"schema_version": 1, "value": "old"})

            backup = config_store.save_versioned_config(
                target,
                {"schema_version": 2, "value": "new"},
            )

            self.assertIsNotNone(backup)
            self.assertEqual(json.loads(backup.read_text(encoding="utf-8"))["value"], "old")
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["value"], "new")
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)

    def test_load_ui_config_migrates_and_backs_up_legacy_file(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            auth_file = data_dir / "ui_auth.json"
            legacy = {
                "username": "admin",
                "password": "password",
                "host": "127.0.0.1",
                "port": 8787,
                "proxy_port": 7928,
                "routing_mode": "auto",
                "force_country": "",
                "routing_ip_type": "all",
                "connection_enabled": True,
                "fixed_node_id": "",
                "favorite_node_ids": [],
                "fav_fail_fallback": False,
                "vpn_exits": [{"id": "default", "enabled": True, "proxy_port": 7928}],
                "singbox": {"enabled": False, "chain_enabled": False, "public_host": "vpn.example.com"},
            }
            config_store.atomic_write_json(auth_file, legacy)

            with patch.object(vpngate_manager, "DATA_DIR", data_dir), \
                 patch.object(vpngate_manager, "UI_CONFIG_FILE", auth_file):
                loaded = vpngate_manager.load_ui_config()

            self.assertEqual(loaded["schema_version"], 2)
            self.assertEqual(loaded["desired_state"]["vpn_exits"]["default"], "running")
            self.assertNotIn("password", loaded)
            self.assertTrue(auth_security.verify_password("password", loaded["password_hash"]))
            backups = list(data_dir.glob("ui_auth.json.v1.*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertNotIn("schema_version", json.loads(backups[0].read_text(encoding="utf-8")))

    def test_invalid_ui_config_is_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            auth_file = data_dir / "ui_auth.json"
            auth_file.write_text("{invalid", encoding="utf-8")

            with patch.object(vpngate_manager, "DATA_DIR", data_dir), \
                 patch.object(vpngate_manager, "UI_CONFIG_FILE", auth_file):
                with self.assertRaises(config_store.ConfigStoreError):
                    vpngate_manager.load_ui_config()

            self.assertEqual(auth_file.read_text(encoding="utf-8"), "{invalid")


class SingBoxRollbackTests(unittest.TestCase):
    def test_failed_reload_restores_previous_runtime_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            old_config = {"inbounds": [{"tag": "old"}], "outbounds": [], "route": {}}
            new_config = {"inbounds": [{"tag": "new"}], "outbounds": [], "route": {}}
            config_store.atomic_write_json(config_path, old_config)

            with patch.object(singbox_manager, "SINGBOX_CONFIG", config_path), \
                 patch.object(singbox_manager, "validate_config"), \
                 patch.object(
                     singbox_manager,
                     "service_action",
                     side_effect=[singbox_manager.SingBoxError("reload failed"), {"running": True}],
                 ) as service_action:
                singbox_manager._write_runtime_config(new_config)
                with self.assertRaisesRegex(singbox_manager.SingBoxError, "已自动恢复旧配置"):
                    singbox_manager.apply_saved_config("reload")

            self.assertEqual(json.loads(config_path.read_text(encoding="utf-8")), old_config)
            self.assertEqual(service_action.call_args_list[0].args, ("reload",))
            self.assertEqual(service_action.call_args_list[1].args, ("restart",))

    def test_failed_first_apply_removes_unusable_runtime_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_store.atomic_write_json(config_path, {"inbounds": [], "outbounds": [], "route": {}})

            with patch.object(singbox_manager, "SINGBOX_CONFIG", config_path), \
                 patch.object(
                     singbox_manager,
                     "service_action",
                     side_effect=[singbox_manager.SingBoxError("start failed"), {"running": False}],
                 ):
                with self.assertRaisesRegex(singbox_manager.SingBoxError, "已移除首次生成的配置"):
                    singbox_manager.apply_saved_config("reload")

            self.assertFalse(config_path.exists())


class RuntimeReconciliationTests(unittest.TestCase):
    def setUp(self):
        vpngate_manager.vpn_exit_retry_states.clear()
        vpngate_manager.vpn_exit_processes.clear()
        vpngate_manager.vpn_exit_runtime_states.clear()

    def test_default_exit_desired_state_controls_connection_switch(self):
        ui_config = {
            "connection_enabled": True,
            "vpn_exits": [{"id": "default", "proxy_port": 7928, "enabled": True}],
            "desired_state": {"vpn_exits": {"default": "running"}},
        }

        vpngate_manager.update_desired_vpn_exit_state(ui_config, "default", "stopped")

        self.assertFalse(ui_config["connection_enabled"])
        self.assertEqual(ui_config["desired_state"]["vpn_exits"]["default"], "stopped")

    def test_auto_default_exit_takes_precedence_over_legacy_fixed_ip_rule(self):
        ui_config = {
            "routing_mode": "fixed_ip",
            "fixed_node_id": "us-fixed",
            "vpn_exits": [{
                "id": "default",
                "node_id": "",
                "country": "日本",
                "ip_type": "residential",
                "proxy_port": 7928,
                "enabled": True,
            }],
        }
        active_node = {
            "id": "jp-auto",
            "country": "日本",
            "ip_type": "mobile",
            "probe_status": "unavailable",
        }
        with patch.object(vpngate_manager, "active_openvpn_node_id", "jp-auto"), \
             patch.object(vpngate_manager, "read_nodes", return_value=[active_node]), \
             patch.object(vpngate_manager, "validate_node_allowed_by_routing") as validate_routing:
            result = vpngate_manager.enforce_active_node_allowed_by_routing(ui_config)

        self.assertIsNone(result)
        validate_routing.assert_not_called()

    def test_reconcile_restores_extra_exits_and_isolates_failures(self):
        exits = [
            {"id": "default", "enabled": True},
            {"id": "usa", "enabled": True},
            {"id": "japan", "enabled": True},
        ]
        ui_config = {
            "desired_state": {
                "singbox": "running",
                "vpn_exits": {"default": "running", "usa": "running", "japan": "running"},
            }
        }

        with patch.object(singbox_manager, "status", return_value={"running": False}), \
             patch.object(singbox_manager, "service_action", return_value={"running": True}) as service_action, \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=exits), \
             patch.object(
                 vpngate_manager,
                 "start_vpn_exit",
                 side_effect=[{"running": True}, RuntimeError("node unavailable")],
             ) as start_exit, \
             patch.object(vpngate_manager, "log_to_json"):
            result = vpngate_manager.reconcile_declared_runtime(ui_config)

        service_action.assert_called_once_with("start")
        self.assertEqual([call.args[0] for call in start_exit.call_args_list], ["usa", "japan"])
        self.assertTrue(result["vpn_exits"]["usa"]["ok"])
        self.assertFalse(result["vpn_exits"]["japan"]["ok"])
        self.assertIn("node unavailable", result["vpn_exits"]["japan"]["error"])

    def test_reconcile_stops_singbox_when_declared_stopped(self):
        ui_config = {"desired_state": {"singbox": "stopped", "vpn_exits": {}}}
        with patch.object(singbox_manager, "status", return_value={"running": True}), \
             patch.object(singbox_manager, "service_action", return_value={"running": False}) as service_action, \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=[]):
            result = vpngate_manager.reconcile_declared_runtime(ui_config)

        service_action.assert_called_once_with("stop")
        self.assertTrue(result["singbox"]["ok"])

    def test_reconcile_stops_extra_exit_declared_stopped(self):
        exit_config = {"id": "usa", "enabled": True}
        ui_config = {"desired_state": {"singbox": "stopped", "vpn_exits": {"usa": "stopped"}}}
        with patch.object(singbox_manager, "status", return_value={"running": False}), \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=[exit_config]), \
             patch.object(vpngate_manager, "vpn_exit_status", return_value={"running": True}), \
             patch.object(vpngate_manager, "stop_vpn_exit", return_value={"running": False}) as stop_exit:
            result = vpngate_manager.reconcile_declared_runtime(ui_config, now=100)

        stop_exit.assert_called_once_with("usa")
        self.assertTrue(result["vpn_exits"]["usa"]["ok"])

    def test_reconcile_uses_exponential_retry_backoff(self):
        exit_config = {"id": "usa", "enabled": True}
        ui_config = {"desired_state": {"singbox": "stopped", "vpn_exits": {"usa": "running"}}}
        with patch.object(singbox_manager, "status", return_value={"running": False}), \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=[exit_config]), \
             patch.object(vpngate_manager, "vpn_exit_status", return_value={"running": False, "runtime": {}}), \
             patch.object(vpngate_manager, "start_vpn_exit", side_effect=RuntimeError("unavailable")) as start_exit, \
             patch.object(vpngate_manager, "log_to_json"):
            first = vpngate_manager.reconcile_declared_runtime(ui_config, now=100)
            second = vpngate_manager.reconcile_declared_runtime(ui_config, now=110)

        self.assertEqual(start_exit.call_count, 1)
        self.assertEqual(first["vpn_exits"]["usa"]["retry_at"], 130)
        self.assertEqual(second["vpn_exits"]["usa"]["retry_at"], 130)
        self.assertEqual(vpngate_manager.vpn_exit_retry_states["usa"]["failures"], 1)

    def test_reconcile_auto_exit_reselects_after_health_failure(self):
        exit_config = {
            "id": "japan",
            "enabled": True,
            "node_id": "",
            "country": "日本",
            "ip_type": "residential",
            "proxy_port": 7929,
            "tun_name": "tun1",
        }
        ui_config = {"desired_state": {"singbox": "stopped", "vpn_exits": {"japan": "running"}}}
        running_status = {
            "running": True,
            "active_node_id": "jp-old",
            "runtime": {"node_id": "jp-old", "health_checked_at": 0},
        }
        with patch.object(singbox_manager, "status", return_value={"running": False}), \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=[exit_config]), \
             patch.object(vpngate_manager, "vpn_exit_status", return_value=running_status), \
             patch.object(
                 vpngate_manager,
                 "check_proxy_health",
                 return_value={"ok": False, "error": "egress unavailable"},
             ) as check_health, \
             patch.object(vpngate_manager, "mark_vpn_exit_node_unavailable") as mark_unavailable, \
             patch.object(vpngate_manager, "stop_vpn_exit", return_value={"running": False}) as stop_exit, \
             patch.object(vpngate_manager, "start_vpn_exit", return_value={"running": True}) as start_exit:
            result = vpngate_manager.reconcile_declared_runtime(ui_config, now=100)

        check_health.assert_called_once_with(proxy_port=7929, proxy_host="127.0.0.1", tun_name="tun1")
        mark_unavailable.assert_called_once_with("jp-old", "egress unavailable")
        stop_exit.assert_called_once_with("japan")
        start_exit.assert_called_once_with("japan")
        self.assertTrue(result["vpn_exits"]["japan"]["ok"])

    def test_singbox_status_degrades_when_exit_process_is_running_but_proxy_is_not_ready(self):
        ui_config = {
            "singbox": {"nodes": [{"id": "node-a", "enabled": True, "chain_enabled": True, "vpn_exit_id": "usa"}]},
            "vpn_exits": [{"id": "usa", "proxy_port": 7929}],
        }
        with patch.object(vpngate_manager, "current_singbox_nodes", return_value=ui_config["singbox"]["nodes"]), \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=ui_config["vpn_exits"]), \
             patch.object(vpngate_manager, "vpn_exit_status", return_value={"id": "usa", "running": True, "phase": "tunnel_ready"}), \
             patch.object(singbox_manager, "status", return_value={"running": True, "installed": True}):
            status = vpngate_manager.singbox_api_status(ui_config)

        self.assertFalse(status["chain_ready"])
        self.assertEqual(status["chain_state"], "degraded")
        self.assertEqual(status["unhealthy_exits"], ["usa"])
        self.assertEqual(status["nodes"][0]["chain_state"], "degraded")

    def test_singbox_status_is_healthy_with_proxy_ready_exit(self):
        ui_config = {
            "singbox": {"nodes": [{"id": "node-a", "enabled": True, "chain_enabled": True, "vpn_exit_id": "usa"}]},
            "vpn_exits": [{"id": "usa", "proxy_port": 7929}],
        }
        with patch.object(vpngate_manager, "current_singbox_nodes", return_value=ui_config["singbox"]["nodes"]), \
             patch.object(vpngate_manager, "current_vpn_exits", return_value=ui_config["vpn_exits"]), \
             patch.object(vpngate_manager, "vpn_exit_status", return_value={"id": "usa", "running": True, "phase": "proxy_ready"}), \
             patch.object(singbox_manager, "status", return_value={"running": True, "installed": True}):
            status = vpngate_manager.singbox_api_status(ui_config)

        self.assertTrue(status["chain_ready"])
        self.assertEqual(status["chain_state"], "healthy")
        self.assertEqual(status["nodes"][0]["chain_state"], "healthy")


if __name__ == "__main__":
    unittest.main()
