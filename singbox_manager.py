"""sing-box configuration and service helpers for the AimiliVPN proxy chain."""

from __future__ import annotations

import json
import ipaddress
import base64
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
import urllib.parse
from pathlib import Path
from typing import Any


SINGBOX_DIR = Path(os.environ.get("SINGBOX_DIR", "/etc/sing-box"))
SINGBOX_BIN = Path(os.environ.get("SINGBOX_BIN", str(SINGBOX_DIR / "bin" / "sing-box")))
SINGBOX_CONFIG = Path(os.environ.get("SINGBOX_CONFIG", str(SINGBOX_DIR / "config.json")))
SINGBOX_INSTALLER = Path(
    os.environ.get("SINGBOX_INSTALLER", str(Path(__file__).resolve().parent / "sing-box" / "install.sh"))
)
SINGBOX_LOG = Path(os.environ.get("SINGBOX_LOG", "/var/log/sing-box/access.log"))
SINGBOX_SERVICE = os.environ.get("SINGBOX_SERVICE", "sing-box")
TLS_CERTIFICATE = SINGBOX_DIR / "bin" / "tls.cer"
TLS_KEY = SINGBOX_DIR / "bin" / "tls.key"
SUPPORTED_PROTOCOLS = {
    "vless-reality",
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "tuic",
    "hysteria2",
    "anytls",
}
PROTOCOL_LABELS = {
    "vless-reality": "VLESS-REALITY",
    "vless": "VLESS (TCP)",
    "vmess": "VMess (TCP)",
    "trojan": "Trojan (TCP)",
    "shadowsocks": "Shadowsocks",
    "socks": "SOCKS5",
    "http": "HTTP",
    "tuic": "TUIC",
    "hysteria2": "Hysteria2",
    "anytls": "AnyTLS",
}
SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
SERVICE_ACTIONS = {"start", "stop", "restart", "reload"}
LISTEN_HOSTS = {"0.0.0.0", "::"}
TLS_PROTOCOLS = {"tuic", "hysteria2", "anytls"}
SERVER_NAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


class SingBoxError(RuntimeError):
    """A safe, user-facing sing-box integration error."""


def _run(command: list[str], timeout: int = 20, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd)
    except FileNotFoundError as exc:
        raise SingBoxError(f"缺少命令: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SingBoxError("命令执行超时") from exc


def _command_error(result: subprocess.CompletedProcess[str], fallback: str) -> str:
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    message = detail[-1] if detail else fallback
    return message[:500]


def installed() -> bool:
    return SINGBOX_BIN.is_file() and os.access(SINGBOX_BIN, os.X_OK)


def _service_manager() -> str | None:
    if shutil.which("systemctl"):
        return "systemd"
    if shutil.which("rc-service"):
        return "openrc"
    return None


def service_action(action: str) -> dict[str, Any]:
    if action not in SERVICE_ACTIONS:
        raise SingBoxError("不支持的 sing-box 服务操作")
    manager = _service_manager()
    if not manager:
        raise SingBoxError("未检测到 systemd 或 OpenRC，无法管理 sing-box 服务")
    if manager == "systemd":
        command_action = "reload-or-restart" if action == "reload" else action
        result = _run(["systemctl", command_action, SINGBOX_SERVICE], timeout=30)
    else:
        command_action = "restart" if action == "reload" else action
        result = _run(["rc-service", SINGBOX_SERVICE, command_action], timeout=30)
    if result.returncode != 0:
        raise SingBoxError(_command_error(result, f"sing-box {action} 失败"))
    if action in {"start", "restart", "reload"}:
        time.sleep(1)
    current = status()
    if action in {"start", "restart", "reload"} and not current["running"]:
        logs = recent_logs(6)
        detail = logs[-1] if logs else current.get("service_detail", "服务启动后立即退出")
        raise SingBoxError(f"sing-box 启动后退出: {detail}")
    return current


def install() -> dict[str, Any]:
    """Install the vendored sing-box manager/core using its local-install path."""
    if installed():
        return status()
    if not SINGBOX_INSTALLER.is_file():
        raise SingBoxError(f"找不到 sing-box 安装脚本: {SINGBOX_INSTALLER}")
    if not (SINGBOX_INSTALLER.parent / "src" / "core.sh").is_file():
        raise SingBoxError("sing-box 安装脚本目录不完整")
    result = _run(["bash", "install.sh", "--local-install"], timeout=600, cwd=SINGBOX_INSTALLER.parent)
    if result.returncode != 0:
        raise SingBoxError(_command_error(result, "sing-box 安装失败"))
    if not installed():
        raise SingBoxError("sing-box 安装命令已结束，但未找到核心文件")
    return status()


def _systemd_status() -> tuple[bool, str]:
    result = _run(["systemctl", "is-active", SINGBOX_SERVICE], timeout=5)
    value = result.stdout.strip()
    return result.returncode == 0 and value == "active", value or "unknown"


def _openrc_status() -> tuple[bool, str]:
    result = _run(["rc-service", SINGBOX_SERVICE, "status"], timeout=5)
    return result.returncode == 0, (result.stdout or result.stderr or "unknown").strip()[:160]


def status() -> dict[str, Any]:
    manager = _service_manager()
    running = False
    service_detail = "未检测到服务管理器"
    if manager == "systemd":
        running, service_detail = _systemd_status()
    elif manager == "openrc":
        running, service_detail = _openrc_status()

    config_exists = SINGBOX_CONFIG.is_file()
    config_error = ""
    settings: dict[str, Any] = {}
    if config_exists:
        try:
            settings = extract_settings(load_runtime_config())
        except SingBoxError as exc:
            config_error = str(exc)

    return {
        "installed": installed(),
        "running": running,
        "service_manager": manager or "none",
        "service_detail": service_detail,
        "config_exists": config_exists,
        "config_error": config_error,
        "settings": redact_settings(settings),
    }


def _generate_reality_keys() -> tuple[str, str]:
    if not installed():
        raise SingBoxError("sing-box 尚未安装，无法生成 Reality 密钥")
    result = _run([str(SINGBOX_BIN), "generate", "reality-keypair"], timeout=15)
    if result.returncode != 0:
        raise SingBoxError(_command_error(result, "生成 Reality 密钥失败"))
    private_match = re.search(r"PrivateKey:\s*(\S+)", result.stdout)
    public_match = re.search(r"PublicKey:\s*(\S+)", result.stdout)
    if not private_match or not public_match:
        raise SingBoxError("无法解析 sing-box 生成的 Reality 密钥")
    return private_match.group(1), public_match.group(1)


def generate_values(kind: str) -> dict[str, str]:
    if kind == "uuid":
        return {"uuid": str(uuid.uuid4())}
    if kind == "short_id":
        return {"short_id": secrets.token_hex(8)}
    if kind == "password":
        return {"password": secrets.token_urlsafe(18)}
    if kind == "reality_keypair":
        private_key, public_key = _generate_reality_keys()
        return {"private_key": private_key, "public_key": public_key}
    raise SingBoxError("不支持的凭据生成类型")


def ensure_tls_keypair() -> None:
    """Create the self-signed TLS material used by QUIC/TLS inbounds once."""
    if TLS_CERTIFICATE.is_file() and TLS_KEY.is_file():
        return
    if not installed():
        raise SingBoxError("sing-box 尚未安装，无法生成 TLS 证书")
    result = _run([str(SINGBOX_BIN), "generate", "tls-keypair", "tls", "-m", "456"], timeout=20)
    if result.returncode != 0:
        raise SingBoxError(_command_error(result, "生成 TLS 证书失败"))
    private_key = re.search(r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----", result.stdout)
    certificate = re.search(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", result.stdout)
    if not private_key or not certificate:
        raise SingBoxError("无法解析 sing-box 生成的 TLS 证书")
    TLS_KEY.parent.mkdir(parents=True, exist_ok=True)
    TLS_KEY.write_text(private_key.group(0) + "\n", encoding="utf-8")
    TLS_CERTIFICATE.write_text(certificate.group(0) + "\n", encoding="utf-8")
    os.chmod(TLS_KEY, 0o600)
    os.chmod(TLS_CERTIFICATE, 0o644)


def default_settings(proxy_port: int) -> dict[str, Any]:
    return {
        "enabled": True,
        "chain_enabled": True,
        "protocol": "vless-reality",
        "listen": "0.0.0.0",
        "port": 4433,
        "uuid": str(uuid.uuid4()),
        "server_name": "www.cloudflare.com",
        "short_id": secrets.token_hex(8),
        "private_key": "",
        "public_key": "",
        "public_host": "",
        "password": secrets.token_urlsafe(18),
        "method": "chacha20-ietf-poly1305",
        "username": "aimilivpn",
        # New sing-box nodes use the host network until a combination explicitly
        # assigns a VPNGate exit.
        "vpn_exit_id": "direct",
        "local_http_port": proxy_port,
        "last_apply_at": 0,
        "last_error": "",
    }


def _as_port(value: Any, field: str, forbidden_ports: set[int]) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise SingBoxError(f"{field} 必须是端口号") from exc
    if not 1 <= port <= 65535:
        raise SingBoxError(f"{field} 必须在 1 至 65535 之间")
    if port in forbidden_ports:
        raise SingBoxError(f"{field} 不能与 Web UI 或本地代理端口冲突")
    return port


def _clean_server_name(value: Any, field: str) -> str:
    name = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(name.strip("[]")))
    except ValueError:
        pass
    if not SERVER_NAME_RE.fullmatch(name):
        raise SingBoxError(f"{field} 必须是有效域名或 IP 地址")
    return name


def _as_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    raise SingBoxError(f"{field} 必须是布尔值")


def normalize_settings(
    raw: dict[str, Any],
    proxy_port: int,
    forbidden_ports: set[int],
    allowed_proxy_ports: set[int] | None = None,
) -> dict[str, Any]:
    base = default_settings(proxy_port)
    for key in base:
        if key in raw:
            base[key] = raw[key]

    protocol = str(base["protocol"] or "").strip().lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise SingBoxError("不支持的 sing-box 入口协议")
    base["protocol"] = protocol
    base["enabled"] = _as_bool(base["enabled"], "启用 sing-box")
    base["chain_enabled"] = _as_bool(base["chain_enabled"], "启用代理链")

    listen = str(base["listen"] or "").strip()
    if listen not in LISTEN_HOSTS:
        raise SingBoxError("监听地址仅支持 0.0.0.0 或 ::")
    base["listen"] = listen
    base["port"] = _as_port(base["port"], "sing-box 入口端口", forbidden_ports)

    if protocol in {"vless-reality", "vless", "vmess", "tuic"}:
        try:
            base["uuid"] = str(uuid.UUID(str(base["uuid"])))
        except (ValueError, TypeError, AttributeError) as exc:
            raise SingBoxError("VLESS/VMess UUID 格式无效") from exc

    base["server_name"] = _clean_server_name(base["server_name"], "Reality SNI")
    public_host = str(base["public_host"] or "").strip()
    if public_host:
        base["public_host"] = _clean_server_name(public_host, "客户端服务器地址")
    else:
        base["public_host"] = ""

    base["short_id"] = str(base["short_id"] or "").strip().lower()
    base["private_key"] = str(base["private_key"] or "").strip()
    base["public_key"] = str(base["public_key"] or "").strip()
    if protocol == "vless-reality":
        if not re.fullmatch(r"[0-9a-f]{2,16}", base["short_id"]) or len(base["short_id"]) % 2:
            raise SingBoxError("Reality short ID 必须为 2 至 16 位的偶数长度十六进制字符串")
        if base["enabled"] and (not base["private_key"] or not base["public_key"]):
            raise SingBoxError("Reality 密钥未生成，请先生成密钥对")

    base["password"] = str(base.get("password") or "")
    base["username"] = str(base.get("username") or "aimilivpn")
    base["method"] = str(base.get("method") or "chacha20-ietf-poly1305").lower()
    if protocol in {"trojan", "shadowsocks", "socks", "http", "tuic", "hysteria2", "anytls"} and base["enabled"] and not base["password"]:
        raise SingBoxError(f"{PROTOCOL_LABELS[protocol]} 密码不能为空")
    if protocol == "shadowsocks" and base["method"] not in SS_METHODS:
        raise SingBoxError("Shadowsocks 加密方式不受支持")

    # A direct node does not use local_http_port. VPNGate-bound nodes are
    # restricted to ports registered by the AimiliVPN exit manager.
    base["vpn_exit_id"] = str(base.get("vpn_exit_id") or "direct").strip()
    allowed_ports = allowed_proxy_ports or {proxy_port}
    try:
        local_http_port = int(base.get("local_http_port", proxy_port))
    except (TypeError, ValueError) as exc:
        raise SingBoxError("VPNGate 出口端口无效") from exc
    if base["vpn_exit_id"] != "direct" and local_http_port not in allowed_ports:
        raise SingBoxError("所选 VPNGate 出口不存在或不可用")
    base["local_http_port"] = local_http_port
    return base


def build_proxy_chain_config(settings: dict[str, Any]) -> dict[str, Any]:
    is_direct = str(settings.get("vpn_exit_id") or "direct") == "direct"
    egress_tag = "direct" if is_direct else "vpngate-chain"
    egress_outbound: dict[str, Any] = {"type": "direct", "tag": egress_tag}
    if not is_direct:
        egress_outbound = {
            "type": "http",
            "tag": egress_tag,
            "server": "127.0.0.1",
            "server_port": settings["local_http_port"],
        }

    protocol = settings["protocol"]
    inbound: dict[str, Any] = {
        "type": "vless" if protocol == "vless-reality" else protocol,
        "tag": f"aimilivpn-{protocol}",
        "listen": settings["listen"],
        "listen_port": settings["port"],
    }
    if protocol == "vless-reality":
        inbound["users"] = [{"uuid": settings["uuid"], "flow": "xtls-rprx-vision"}]
        inbound["tls"] = {
            "enabled": True,
            "server_name": settings["server_name"],
            "reality": {
                "enabled": True,
                "handshake": {"server": settings["server_name"], "server_port": 443},
                "private_key": settings["private_key"],
                "short_id": [settings["short_id"]],
            },
        }
    elif protocol == "vless":
        inbound["users"] = [{"uuid": settings["uuid"]}]
    elif protocol == "vmess":
        inbound["users"] = [{"uuid": settings["uuid"]}]
    elif protocol == "trojan":
        inbound["users"] = [{"name": settings["username"], "password": settings["password"]}]
    elif protocol == "shadowsocks":
        inbound["method"] = settings["method"]
        inbound["password"] = settings["password"]
    elif protocol in {"socks", "http"}:
        inbound["users"] = [{"username": settings["username"], "password": settings["password"]}]
    elif protocol == "tuic":
        inbound["users"] = [{"uuid": settings["uuid"], "password": settings["password"]}]
        inbound["congestion_control"] = "bbr"
        inbound["tls"] = {
            "enabled": True,
            "alpn": ["h3"],
            "key_path": str(TLS_KEY),
            "certificate_path": str(TLS_CERTIFICATE),
        }
    elif protocol == "hysteria2":
        inbound["users"] = [{"password": settings["password"]}]
        inbound["tls"] = {
            "enabled": True,
            "alpn": ["h3"],
            "key_path": str(TLS_KEY),
            "certificate_path": str(TLS_CERTIFICATE),
        }
    elif protocol == "anytls":
        inbound["users"] = [{"password": settings["password"]}]
        inbound["tls"] = {
            "enabled": True,
            "key_path": str(TLS_KEY),
            "certificate_path": str(TLS_CERTIFICATE),
        }
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [inbound],
        "outbounds": [egress_outbound, {"type": "block", "tag": "block"}],
        "route": {"final": egress_tag},
    }


def validate_config(config: dict[str, Any]) -> None:
    if not installed():
        raise SingBoxError("sing-box 尚未安装")
    SINGBOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".aimilivpn-check-", suffix=".json", dir=SINGBOX_CONFIG.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        result = _run([str(SINGBOX_BIN), "check", "-c", str(temp_path)], timeout=20)
        if result.returncode != 0:
            raise SingBoxError(_command_error(result, "sing-box 配置校验失败"))
    finally:
        temp_path.unlink(missing_ok=True)


def save_config(settings: dict[str, Any], proxy_port: int, forbidden_ports: set[int]) -> dict[str, Any]:
    normalized = normalize_settings(settings, proxy_port, forbidden_ports)
    if normalized["protocol"] in TLS_PROTOCOLS:
        ensure_tls_keypair()
    config = build_proxy_chain_config(normalized)
    validate_config(config)

    SINGBOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".aimilivpn-config-", suffix=".json", dir=SINGBOX_CONFIG.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        if SINGBOX_CONFIG.exists():
            backup = SINGBOX_CONFIG.with_name("config.aimilivpn-backup.json")
            shutil.copy2(SINGBOX_CONFIG, backup)
            os.chmod(backup, 0o600)
        os.replace(temp_path, SINGBOX_CONFIG)
    finally:
        temp_path.unlink(missing_ok=True)

    normalized["last_apply_at"] = int(time.time())
    normalized["last_error"] = ""
    return normalized


def new_node(proxy_port: int, protocol: str = "vless-reality") -> dict[str, Any]:
    settings = default_settings(proxy_port)
    settings["id"] = secrets.token_hex(6)
    settings["name"] = PROTOCOL_LABELS.get(protocol, protocol)
    settings["protocol"] = protocol
    return settings


def normalize_nodes(
    raw_nodes: Any,
    proxy_port: int,
    forbidden_ports: set[int],
    allowed_proxy_ports: set[int] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise SingBoxError("至少需要保留一个 sing-box 协议节点")
    if len(raw_nodes) > 32:
        raise SingBoxError("协议节点数量不能超过 32 个")

    nodes: list[dict[str, Any]] = []
    used_ports = set(forbidden_ports)
    node_ids: set[str] = set()
    for raw in raw_nodes:
        if not isinstance(raw, dict):
            raise SingBoxError("协议节点格式无效")
        node_id = str(raw.get("id") or secrets.token_hex(6)).strip()
        if not re.fullmatch(r"[a-zA-Z0-9_-]{4,40}", node_id) or node_id in node_ids:
            raise SingBoxError("协议节点 ID 无效或重复")
        normalized = normalize_settings(raw, proxy_port, used_ports, allowed_proxy_ports)
        normalized["id"] = node_id
        normalized["name"] = str(raw.get("name") or PROTOCOL_LABELS[normalized["protocol"]]).strip()[:80]
        if not normalized["name"]:
            normalized["name"] = PROTOCOL_LABELS[normalized["protocol"]]
        nodes.append(normalized)
        node_ids.add(node_id)
        used_ports.add(normalized["port"])
    return nodes


def build_proxy_chain_nodes(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    active_nodes = [node for node in nodes if node["enabled"] and node["chain_enabled"]]
    if not active_nodes:
        raise SingBoxError("至少需要启用一个协议节点")
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    outbound_tags: dict[int, str] = {}
    for node in active_nodes:
        is_direct = str(node.get("vpn_exit_id") or "direct") == "direct"
        port = node["local_http_port"]
        outbound_key = -1 if is_direct else port
        outbound_tag = outbound_tags.get(outbound_key)
        if outbound_tag is None:
            outbound_tag = "direct" if is_direct else f"vpngate-chain-{port}"
            outbound_tags[outbound_key] = outbound_tag
            outbounds.append(
                {"type": "direct", "tag": outbound_tag}
                if is_direct else {
                    "type": "http",
                    "tag": outbound_tag,
                    "server": "127.0.0.1",
                    "server_port": port,
                }
            )
        inbound = build_proxy_chain_config(node)["inbounds"][0]
        inbound_tag = f"aimilivpn-{node['id']}"
        inbound["tag"] = inbound_tag
        inbounds.append(inbound)
        rules.append({"inbound": [inbound_tag], "outbound": outbound_tag})
    outbounds.append({"type": "block", "tag": "block"})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "block"},
    }


def save_nodes(
    raw_nodes: Any,
    proxy_port: int,
    forbidden_ports: set[int],
    allowed_proxy_ports: set[int] | None = None,
) -> list[dict[str, Any]]:
    nodes = normalize_nodes(raw_nodes, proxy_port, forbidden_ports, allowed_proxy_ports)
    if any(node["protocol"] in TLS_PROTOCOLS for node in nodes):
        ensure_tls_keypair()
    config = build_proxy_chain_nodes(nodes)
    validate_config(config)

    SINGBOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".aimilivpn-config-", suffix=".json", dir=SINGBOX_CONFIG.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        if SINGBOX_CONFIG.exists():
            backup = SINGBOX_CONFIG.with_name("config.aimilivpn-backup.json")
            shutil.copy2(SINGBOX_CONFIG, backup)
            os.chmod(backup, 0o600)
        os.replace(temp_path, SINGBOX_CONFIG)
    finally:
        temp_path.unlink(missing_ok=True)

    timestamp = int(time.time())
    for node in nodes:
        node["last_apply_at"] = timestamp
        node["last_error"] = ""
    return nodes


def load_runtime_config() -> dict[str, Any]:
    if not SINGBOX_CONFIG.exists():
        raise SingBoxError("尚未找到 sing-box 配置文件")
    try:
        data = json.loads(SINGBOX_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SingBoxError("无法读取 sing-box 配置文件") from exc
    if not isinstance(data, dict):
        raise SingBoxError("sing-box 配置文件格式无效")
    return data


def extract_settings(config: dict[str, Any]) -> dict[str, Any]:
    inbounds = config.get("inbounds")
    outbounds = config.get("outbounds")
    if not isinstance(inbounds, list) or not isinstance(outbounds, list):
        raise SingBoxError("sing-box 配置不包含代理链")
    inbound = next((item for item in inbounds if isinstance(item, dict) and str(item.get("tag", "")).startswith("aimilivpn-")), None)
    outbound = next((item for item in outbounds if isinstance(item, dict) and item.get("tag") == "vpngate-chain"), None)
    if not inbound or not outbound:
        raise SingBoxError("当前 sing-box 配置不是 AimiliVPN 管理的代理链")
    protocol = str(inbound.get("type") or "")
    protocol = "vless-reality" if protocol == "vless" and (inbound.get("tls") or {}).get("reality", {}).get("enabled") else protocol
    users = inbound.get("users") or [{}]
    tls = inbound.get("tls") or {}
    reality = tls.get("reality") or {}
    short_ids = reality.get("short_id") or [""]
    first_user = users[0] if isinstance(users[0], dict) else {}
    return {
        "enabled": True,
        "chain_enabled": True,
        "protocol": protocol,
        "listen": inbound.get("listen", "0.0.0.0"),
        "port": inbound.get("listen_port", 4433),
        "uuid": first_user.get("uuid", ""),
        "server_name": tls.get("server_name", ""),
        "short_id": short_ids[0] if isinstance(short_ids, list) and short_ids else "",
        "private_key": reality.get("private_key", ""),
        "public_key": "",
        "public_host": "",
        "local_http_port": outbound.get("server_port", 7928),
        "password": inbound.get("password", first_user.get("password", "")),
        "method": inbound.get("method", "chacha20-ietf-poly1305"),
        "username": first_user.get("username", first_user.get("name", "aimilivpn")),
    }


def redact_settings(settings: dict[str, Any]) -> dict[str, Any]:
    redacted = settings.copy()
    for key in ("private_key", "password"):
        if redacted.get(key):
            redacted[key] = "***"
    return redacted


def client_info(settings: dict[str, Any]) -> dict[str, str]:
    host = str(settings.get("public_host") or "").strip()
    if not host:
        raise SingBoxError("请先设置客户端服务器地址或域名")
    protocol = settings.get("protocol", "vless-reality")
    label = "AimiliVPN-" + PROTOCOL_LABELS.get(protocol, protocol)
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if protocol == "vless-reality":
        if not settings.get("public_key"):
            raise SingBoxError("缺少 Reality 公钥，请重新生成密钥对后保存")
        query = (
            f"encryption=none&security=reality&sni={urllib.parse.quote(settings['server_name'])}&fp=chrome"
            f"&pbk={urllib.parse.quote(settings['public_key'])}&sid={settings['short_id']}&type=tcp&flow=xtls-rprx-vision"
        )
        uri = f"vless://{settings['uuid']}@{host_part}:{settings['port']}?{query}#{label}"
    elif protocol == "vless":
        uri = f"vless://{settings['uuid']}@{host_part}:{settings['port']}?encryption=none&type=tcp#{label}"
    elif protocol == "vmess":
        payload = {"v": "2", "ps": label, "add": host, "port": str(settings["port"]), "id": settings["uuid"], "aid": "0", "scy": "auto", "net": "tcp", "type": "none"}
        encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        uri = f"vmess://{encoded}"
    elif protocol == "shadowsocks":
        userinfo = base64.urlsafe_b64encode(f"{settings['method']}:{settings['password']}".encode()).decode().rstrip("=")
        uri = f"ss://{userinfo}@{host_part}:{settings['port']}#{urllib.parse.quote(label)}"
    elif protocol in {"socks", "http"}:
        scheme = "socks5" if protocol == "socks" else "http"
        userinfo = f"{urllib.parse.quote(settings['username'])}:{urllib.parse.quote(settings['password'])}@"
        uri = f"{scheme}://{userinfo}{host_part}:{settings['port']}"
    elif protocol == "trojan":
        uri = f"trojan://{urllib.parse.quote(settings['password'])}@{host_part}:{settings['port']}?security=none&type=tcp#{urllib.parse.quote(label)}"
    elif protocol == "tuic":
        uri = (
            f"tuic://{settings['uuid']}:{urllib.parse.quote(settings['password'])}@{host_part}:{settings['port']}"
            f"?alpn=h3&insecure=1&congestion_control=bbr#{urllib.parse.quote(label)}"
        )
    elif protocol == "hysteria2":
        uri = (
            f"hysteria2://{urllib.parse.quote(settings['password'])}@{host_part}:{settings['port']}"
            f"?alpn=h3&insecure=1#{urllib.parse.quote(label)}"
        )
    elif protocol == "anytls":
        uri = f"anytls://{urllib.parse.quote(settings['password'])}@{host_part}:{settings['port']}?insecure=1#{urllib.parse.quote(label)}"
    else:
        raise SingBoxError("当前入口协议暂不支持客户端 URI")
    return {"protocol": protocol, "uri": uri}


def recent_logs(limit: int = 80) -> list[str]:
    limit = min(max(int(limit), 1), 200)
    if _service_manager() == "systemd":
        result = _run(["journalctl", "-u", SINGBOX_SERVICE, "-n", str(limit), "--no-pager", "-o", "cat"], timeout=10)
        if result.returncode == 0:
            return [line for line in result.stdout.splitlines() if line][-limit:]
    try:
        return SINGBOX_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except OSError:
        return []
