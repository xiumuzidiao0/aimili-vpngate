import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config_store
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
    def test_default_exit_desired_state_controls_connection_switch(self):
        ui_config = {
            "connection_enabled": True,
            "vpn_exits": [{"id": "default", "proxy_port": 7928, "enabled": True}],
            "desired_state": {"vpn_exits": {"default": "running"}},
        }

        vpngate_manager.update_desired_vpn_exit_state(ui_config, "default", "stopped")

        self.assertFalse(ui_config["connection_enabled"])
        self.assertEqual(ui_config["desired_state"]["vpn_exits"]["default"], "stopped")

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


if __name__ == "__main__":
    unittest.main()
