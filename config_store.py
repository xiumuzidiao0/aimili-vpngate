from __future__ import annotations

import copy
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


CURRENT_SCHEMA_VERSION = 2
MAX_CONFIG_BACKUPS = 5


class ConfigStoreError(RuntimeError):
    """Raised when persisted configuration cannot be safely loaded or saved."""


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigStoreError(f"无法读取配置文件: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigStoreError(f"配置文件不是有效 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ConfigStoreError(f"配置文件根节点必须是对象: {path}")
    return value


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_json(path: Path, data: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _backup_path(path: Path, schema_version: int) -> Path:
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    candidate = path.with_name(f"{path.name}.v{schema_version}.{timestamp}.bak")
    suffix = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.v{schema_version}.{timestamp}.{suffix}.bak")
        suffix += 1
    return candidate


def prune_backups(path: Path, keep: int = MAX_CONFIG_BACKUPS) -> None:
    backups = sorted(
        path.parent.glob(f"{path.name}.v*.bak"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for old_backup in backups[max(keep, 0):]:
        old_backup.unlink(missing_ok=True)


def backup_file(path: Path, schema_version: int, keep: int = MAX_CONFIG_BACKUPS) -> Path | None:
    if not path.is_file():
        return None
    backup = _backup_path(path, schema_version)
    payload = path.read_bytes()
    fd, temp_name = tempfile.mkstemp(prefix=f".{backup.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, backup)
        _fsync_directory(path.parent)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    prune_backups(path, keep)
    return backup


def save_versioned_config(path: Path, data: dict[str, Any], create_backup: bool = True) -> Path | None:
    previous_version = 1
    if path.is_file():
        try:
            previous_version = int(read_json_object(path).get("schema_version", 1))
        except (ConfigStoreError, TypeError, ValueError):
            previous_version = 1
    backup = backup_file(path, previous_version) if create_backup else None
    atomic_write_json(path, data)
    return backup


def migrate_ui_config(raw: dict[str, Any], now: int | None = None) -> tuple[dict[str, Any], bool]:
    migrated = copy.deepcopy(raw)
    try:
        version = int(migrated.get("schema_version", 1))
    except (TypeError, ValueError) as exc:
        raise ConfigStoreError("配置 schema_version 无效") from exc
    if version < 1:
        raise ConfigStoreError("配置 schema_version 不能小于 1")
    if version > CURRENT_SCHEMA_VERSION:
        raise ConfigStoreError(
            f"配置版本 {version} 高于当前程序支持的版本 {CURRENT_SCHEMA_VERSION}"
        )

    changed = False
    original_version = version
    if version == 1:
        singbox = migrated.get("singbox") if isinstance(migrated.get("singbox"), dict) else {}
        exits = migrated.get("vpn_exits") if isinstance(migrated.get("vpn_exits"), list) else []
        desired_exits: dict[str, str] = {}
        for item in exits:
            if not isinstance(item, dict):
                continue
            exit_id = str(item.get("id") or "").strip()
            if exit_id:
                desired_exits[exit_id] = "running" if exit_id == "default" and item.get("enabled", True) else "stopped"
        migrated["desired_state"] = {
            "singbox": "running" if singbox.get("enabled") and singbox.get("chain_enabled") else "stopped",
            "vpn_exits": desired_exits,
        }
        version = 2
        changed = True

    if migrated.get("schema_version") != CURRENT_SCHEMA_VERSION:
        migrated["schema_version"] = CURRENT_SCHEMA_VERSION
        changed = True
    if changed:
        migrated["migrated_from"] = original_version
        migrated["migrated_at"] = int(time.time()) if now is None else int(now)
    return migrated, changed
