# AimiliVPN + sing-box 合并实施任务书

## 1. 文档目的

本文档定义将当前 AimiliVPN（VPNGate/OpenVPN 管理器）与 `sing-box/` 协议服务项目合并为一个可安装、可管理、可验证的代理网关产品所需的目标、边界、架构、接口、配置和验收标准。

本文档是后续开发、代码评审、测试和发布的执行依据。除非另有说明，默认目标平台为以 root 运行的 Linux VPS，支持 systemd；OpenRC 作为兼容路径保留。

## 2. 当前项目事实

### 2.1 AimiliVPN

- 主程序：`vpngate_manager.py`
- 工具模块：`vpn_utils.py`
- 本地代理：`proxy_server.py`
- 安装入口：`install.sh`
- Web UI 和 API：内嵌在 `vpngate_manager.py` 的 `INDEX_HTML` 与 `Handler`
- 节点数据：`vpngate_data/nodes.json`
- UI 配置：`vpngate_data/ui_auth.json`
- 状态数据：`vpngate_data/state.json`
- 默认管理端口：`8787`
- 默认本地 HTTP/SOCKS5 端口：`7928`
- 默认监听地址：
  - Web UI：`::`
  - 本地代理：`127.0.0.1`
- VPN 出口：OpenVPN 节点连接到 `tun0`，代理连接通过 `tun0` 发出。

### 2.2 sing-box

- 目录：`sing-box/`
- 当前项目类型：Shell 安装和配置管理脚本，不是 Python 库。
- 支持的协议包括 VLESS-REALITY、TUIC、Hysteria2、Trojan、Shadowsocks、VMess、AnyTLS 等。
- 默认安装目录：`/etc/sing-box`
- 默认核心路径：`/etc/sing-box/bin/sing-box`
- 默认配置目录：`/etc/sing-box/conf`
- 默认主配置：`/etc/sing-box/config.json`
- 服务管理：systemd 或 OpenRC。
- 当前脚本具备独立安装、生成配置、启动和管理能力，但没有 AimiliVPN Web API 集成。

## 3. 产品目标

合并后，用户只执行一个安装脚本，即可获得以下能力：

1. 自动安装 AimiliVPN、OpenVPN、sing-box 及必要依赖。
2. 通过 AimiliVPN Web UI 获取、测速、筛选和切换 VPNGate 节点。
3. 通过同一个 Web UI 配置代理链：
   - 对外入口：sing-box 的 VLESS/Reality、TUIC、Hysteria2 等协议。
   - 中间转发：sing-box HTTP 出站。
   - VPN 出口：AimiliVPN 本地 HTTP 代理 `127.0.0.1:7928`。
   - 最终出口：当前选中的 VPNGate OpenVPN 节点。
4. 在 Web UI 查看 VPN、AimiliVPN 本地代理和 sing-box 的运行状态。
5. 在 Web UI 修改入口协议、端口、凭据以及代理链开关，并在配置变更后安全重载 sing-box。
6. 支持节点自动切换时代理链自动继续工作，不需要用户重新配置客户端。
7. 保留现有 CLI 安装、更新、启动、停止、重启和卸载能力。

## 4. 非目标

以下内容不属于第一阶段必须完成的范围：

- 不把 sing-box 核心代码编译进 Python。
- 不替换现有 OpenVPN 节点连接和策略路由实现。
- 不让 sing-box 接管 `tun0`、iptables 或系统默认路由。
- 不在第一阶段实现多台 VPN 节点同时出站。
- 不在第一阶段实现按用户、域名或客户端分别选择不同 VPN 节点。
- 不默认将 AimiliVPN 的 `7928` 本地代理暴露到公网。
- 不直接复制 sing-box 的第三方运行时代码到 Python 模块；只通过配置文件、命令行和服务管理接口集成。

## 5. 目标架构

```text
                         管理平面
      浏览器 ────────> AimiliVPN Web UI :8787
                            │
                            ├── VPNGate 节点获取/测速/筛选
                            ├── OpenVPN 连接与自动切换
                            ├── AimiliVPN 本地 HTTP/SOCKS5 :7928
                            └── sing-box 配置生成/校验/重载

                         数据平面
+----------------+   +--------------------+   +--------------------+
| 外部客户端     |-->| sing-box 入站       |-->| sing-box HTTP 出站  |
| VLESS/TUIC/... |   | 公网端口            |   | 127.0.0.1:7928      |
+----------------+   +--------------------+   +--------------------+
                                                        │
                                                        v
                                             +--------------------+
                                             | AimiliVPN 代理      |
                                             | tun0 / OpenVPN      |
                                             +--------------------+
                                                        │
                                                        v
                                                   Internet
```

### 5.1 进程职责

| 组件 | 职责 | 监听/控制 | 生命周期 |
|---|---|---|---|
| `aimilivpn.service` | Web UI、节点同步、OpenVPN、内置代理 | `8787`、`7928`、`tun0` | 主服务常驻 |
| `sing-box.service` | 公网协议入口和代理链转发 | 用户配置的入口端口 | 独立常驻 |
| `openvpn` | 连接 VPNGate 节点 | 动态 `tun0` | 由 AimiliVPN 管理 |

### 5.2 关键约束

1. `sing-box` 的 HTTP 出站必须指向 `127.0.0.1:7928`。
2. `7928` 默认仅监听回环地址，避免形成未授权公网代理。
3. sing-box 的公网入口端口不得与 Web UI、AimiliVPN 本地代理端口冲突。
4. VPNGate 节点切换只改变 OpenVPN 出口，不改变 sing-box 入站端口和客户端配置。
5. AimiliVPN 停止或无可用节点时，sing-box 可以继续运行，但代理链健康状态必须显示为不可用；不能误报为正常出站。
6. 配置写入必须使用临时文件 + 原子替换，并在重载前执行 `sing-box check`。

## 6. 功能需求

### 6.1 一键安装

安装脚本必须：

- 检测 root 权限、CPU 架构、包管理器和 init 系统。
- 安装 OpenVPN、Python、curl、iptables/iproute2、psmisc、jq 等依赖。
- 安装 AimiliVPN 服务。
- 安装 sing-box 核心和管理脚本，优先复用仓库内 `sing-box/` 的安装逻辑。
- 创建 `sing-box.service`，并设置为随系统启动。
- 创建共享配置目录和数据目录。
- 生成随机 Web UI 凭据，并在安装结束时打印安全访问地址。
- 初始化一个可用的 sing-box 入口配置，或明确提示用户通过 Web UI 完成首次配置。
- 不覆盖已有 `ui_auth.json`、VPN 节点数据和 sing-box 配置，除非用户明确执行重装。

### 6.2 Web UI 节点信息

现有节点表继续作为唯一 VPNGate 节点数据源，至少展示：

- 节点 ID、IP、端口、国家/地区。
- 运营商、ASN、IP 类型、质量评分。
- Ping/测速状态、最近检测时间。
- 当前活动节点。
- 收藏、固定节点、固定地区和自动切换状态。

新增代理链摘要区域，显示：

- 当前活动 VPN 节点。
- AimiliVPN 本地代理地址。
- sing-box 是否安装。
- sing-box 服务状态。
- sing-box 当前入口协议和监听端口。
- 代理链是否启用。
- 最近一次配置校验、重载和错误信息。

### 6.3 Web UI 代理链设置

新增“代理链 / sing-box”设置面板，至少支持：

- 启用/停用 sing-box 服务。
- 启用/停用代理链。
- 入口协议选择：第一阶段至少支持 `VLESS-REALITY`，预留 `TUIC`、`Hysteria2`、`Trojan`、`Shadowsocks`。
- 公网监听地址，默认 `0.0.0.0` 或 `::`，并在 UI 明确提示公网暴露风险。
- 公网监听端口，默认随机或安装时生成。
- UUID/密码等入口凭据自动生成和重新生成。
- Reality 所需的 private key、public key、server name、short ID。
- sing-box 出站类型固定为 SOCKS5，目标默认为 `127.0.0.1:7928`。
- 是否携带 AimiliVPN 本地代理认证。
- 配置预览、校验、保存、重载。
- 客户端连接 URL/参数复制。
- 端口冲突检查。

### 6.4 服务控制

Web UI 需要提供以下操作：

- 安装 sing-box（未安装时）。
- 启动、停止、重启 sing-box。
- 校验当前配置。
- 应用配置并重载。
- 查看最近错误和服务日志摘要。

服务控制必须限制为已认证 Web UI 请求，并设置超时，避免阻塞 HTTP 工作线程。

## 7. 后端实现任务

### 7.1 新增管理模块

建议新增 `singbox_manager.py`，负责：

- 运行时路径常量。
- 读取和规范化 sing-box 配置。
- 生成代理链 JSON。
- 生成 VLESS-REALITY 等入口参数。
- 调用 `sing-box check`。
- 调用 systemd/OpenRC 管理命令。
- 查询进程和服务状态。
- 获取配置文件、日志和最近错误。
- 使用白名单字段，禁止 Web UI 直接提交任意命令或任意 JSON。

建议公开接口：

```python
def load_singbox_config() -> dict[str, Any]: ...
def save_singbox_config(payload: dict[str, Any]) -> dict[str, Any]: ...
def build_proxy_chain_config(settings: dict[str, Any]) -> dict[str, Any]: ...
def validate_singbox_config(config: dict[str, Any]) -> tuple[bool, str]: ...
def singbox_status() -> dict[str, Any]: ...
def singbox_service_action(action: str) -> dict[str, Any]: ...
def singbox_client_info() -> dict[str, Any]: ...
```

### 7.2 配置文件模型

建议将 UI 配置扩展为以下结构，实际保存时允许向后兼容旧的扁平字段：

```json
{
  "singbox": {
    "enabled": true,
    "chain_enabled": true,
    "protocol": "vless-reality",
    "listen": "0.0.0.0",
    "port": 4433,
    "uuid": "generated-uuid",
    "password": "",
    "server_name": "www.cloudflare.com",
    "short_id": "generated-hex",
    "private_key": "generated-private-key",
    "public_key": "generated-public-key",
    "local_http_port": 7928,
    "config_path": "/etc/sing-box/config.json",
    "last_apply_at": 0,
    "last_error": ""
  }
}
```

敏感字段要求：

- `password`、private key、代理认证密码不写入普通日志。
- 配置文件权限设置为 `0600`。
- API 返回时默认脱敏，只有用户明确请求客户端连接信息时才返回必要字段。
- 旧配置缺少 `singbox` 字段时自动补默认值，不破坏旧安装。

### 7.3 Web API

新增 GET：

| 路径 | 用途 |
|---|---|
| `/api/singbox/status` | 安装状态、服务状态、配置摘要、链路健康状态 |
| `/api/singbox/config` | 获取脱敏后的当前配置 |
| `/api/singbox/client_info` | 获取客户端连接 URL/参数 |
| `/api/singbox/logs` | 获取最近 sing-box 日志摘要 |

新增 POST：

| 路径 | 用途 |
|---|---|
| `/api/singbox/config` | 校验并保存配置，可选立即应用 |
| `/api/singbox/action` | `install`、`start`、`stop`、`restart`、`reload`、`validate` |
| `/api/singbox/regenerate` | 重新生成 UUID、Reality key 或 short ID |

统一响应格式：

```json
{
  "ok": true,
  "message": "配置已应用",
  "data": {}
}
```

错误响应必须包含用户可读信息；内部命令的完整 stderr 只写入日志，不直接暴露路径和敏感参数。

### 7.4 网关状态扩展

扩展现有 `/api/gateway_status`：

- 增加 `sing-box` 服务项。
- 增加 `proxy_chain` 健康项。
- 将“本地代理可监听”和“代理链可访问公网”分开表示。
- 当 `tun0` 不存在或没有活动节点时，代理链显示 `degraded`/`stopped`，而不是单纯显示 sing-box 进程正常。

## 8. sing-box 配置要求

第一阶段建议生成最小可用的 VLESS-REALITY 配置：

- `inbounds`：VLESS TCP Reality。
- `outbounds[0]`：HTTP，目标 `127.0.0.1:7928`。
- `outbounds[1]`：`block`，作为失败兜底，避免回退直连。
- `route.final`：指向 HTTP 出站。
- DNS 按 sing-box 当前版本支持的稳定配置生成。
- 不启用 TUN 入站，避免与 OpenVPN `tun0` 冲突。
- 不生成 direct final route，防止绕过 VPNGate 出口。

示意结构：

```json
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "0.0.0.0",
      "listen_port": 4433,
      "users": [{ "uuid": "..." }],
      "tls": {
        "enabled": true,
        "server_name": "www.cloudflare.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.cloudflare.com", "server_port": 443 },
          "private_key": "...",
          "short_id": ["..."]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "http",
      "tag": "vpngate-chain",
      "server": "127.0.0.1",
      "server_port": 7928
    },
    { "type": "block", "tag": "block" }
  ],
  "route": { "final": "vpngate-chain" }
}
```

正式实现必须根据实际安装的 sing-box 版本执行 `sing-box check`，不能只依赖 JSON 结构判断有效。

## 9. 安装脚本改造任务

### 9.1 单一入口

`install.sh` 继续作为唯一入口，新增步骤：

1. 安装 AimiliVPN 依赖。
2. 部署 AimiliVPN 代码和 `sing-box/` 管理脚本。
3. 安装 sing-box 核心；支持自定义版本和安装代理。
4. 创建 sing-box 目录、配置目录、日志目录和权限。
5. 创建 `sing-box.service`。
6. 写入初始 `ui_auth.json` 和 sing-box 默认配置。
7. 启用并启动 `aimilivpn.service`、`sing-box.service`。
8. 等待 AimiliVPN 初始化节点；显示 Web UI 地址、sing-box 入口地址和当前状态。

### 9.2 更新和卸载

- `ml update` 同时更新 AimiliVPN 和 sing-box 管理代码，保留用户配置。
- `ml restart` 可同时重启两个服务。
- `ml status` 显示两个服务、当前 VPN 节点、代理链状态。
- `ml uninstall` 必须明确询问是否删除 `/etc/sing-box` 配置和密钥。
- 卸载失败时不能删除用户的 VPNGate 节点数据或备份配置。

### 9.3 网络和防火墙提示

- Web UI 端口和 sing-box 公网入口端口必须分别提示用户放行。
- `7928` 默认不要求公网放行。
- 安装脚本不应默认开放任意公网端口；如需要自动操作防火墙，必须提供显式选项。

## 10. 安全要求

1. Web API 必须沿用现有会话认证和 secret path 校验。
2. 所有 sing-box 操作使用固定动作白名单，禁止拼接用户输入执行 Shell。
3. 端口必须限制为 `1-65535`，并拒绝与 Web UI、`7928`、已监听端口冲突。
4. 公网入口启用认证；不允许生成无用户凭据的开放代理。
5. Reality private key、UUID、代理密码、Web UI 密码不得写入日志。
6. 配置文件和认证文件权限为 `0600`，目录权限按最小权限设置。
7. 保存配置前必须做字段校验、大小限制和协议白名单校验。
8. 配置校验失败时保留旧的可运行配置。
9. sing-box 出站固定为 VPNGate 本地代理，禁止 UI 配置为未经确认的 direct 出站。
10. 服务命令设置超时，并限制 stdout/stderr 大小，防止日志或请求线程被阻塞。

## 11. 测试计划

### 11.1 静态和单元测试

- 配置默认值和旧配置迁移。
- 端口、协议、UUID、Reality key、short ID 校验。
- 敏感字段脱敏。
- JSON 原子写入和损坏配置恢复。
- `sing-box check` 成功、失败和核心不存在场景。
- systemd/OpenRC 命令白名单和错误处理。
- API 未认证、参数缺失、非法动作和端口冲突。

### 11.2 集成测试

在具备 root、OpenVPN、TUN 和 sing-box 的 Linux 环境验证：

1. 全新安装成功。
2. AimiliVPN 获取节点并连接到活动节点。
3. sing-box 启动并监听入口端口。
4. 客户端通过 sing-box 入口访问公网，出口 IP 与 VPNGate 活动节点一致。
5. 切换 VPNGate 节点后，sing-box 入站端口不变且新出口生效。
6. VPN 断开时，代理链显示异常且不发生直连泄漏。
7. Web UI 保存配置、校验、重载和回滚正常。
8. 机器重启后两个服务按正确顺序恢复。
9. 旧版 AimiliVPN 配置升级不丢失节点、凭据和路由设置。

### 11.3 安全测试

- 未认证请求不能调用 sing-box API。
- 不能通过 API 执行任意命令。
- 公网端口无认证时配置被拒绝。
- 代理链断开时无 direct fallback。
- 日志和 API 响应不泄露 private key、密码和完整认证信息。

## 12. 验收标准

满足以下条件才算第一阶段完成：

- 在干净 Linux VPS 上执行一个安装命令即可部署两套服务。
- Web UI 能显示 VPNGate 节点列表和当前活动节点。
- Web UI 能创建并保存至少一个 VLESS-REALITY 入口。
- Web UI 能显示 sing-box、AimiliVPN 本地代理、OpenVPN 和代理链状态。
- 使用生成的客户端参数连接后，流量路径确实为 sing-box -> `127.0.0.1:7928` -> `tun0` -> VPNGate 节点。
- 切换节点后无需修改客户端配置，出口 IP 能随之变化。
- sing-box 配置错误不会中断现有可用配置。
- 重启、升级、卸载均不会意外删除用户配置。
- 默认情况下 `7928` 不暴露公网，公网入口必须认证。
- 安装脚本、后端 API、Web UI 和文档均有对应变更记录。

## 13. 实施顺序

### 阶段 A：后端基础

- 新增 `singbox_manager.py`。
- 增加配置模型、默认值、迁移、原子写入和状态查询。
- 增加配置生成、校验、服务控制和代理链健康检查。
- 为现有 `ui_auth.json` 增加兼容字段。

### 阶段 B：Web API 与 UI

- 增加 sing-box 状态和配置 API。
- 扩展网关状态 API。
- 在现有管理菜单中加入代理链设置面板。
- 加入客户端连接信息和错误显示。

### 阶段 C：安装与服务

- 修改 `install.sh`，将 sing-box 安装、服务和初始化纳入单一流程。
- 修改 CLI 管理命令，支持双服务状态和生命周期管理。
- 增加升级、卸载和回滚逻辑。

### 阶段 D：验证与发布

- 执行静态检查、API 测试和配置测试。
- 在带 TUN 的 Linux VPS 进行真实链路测试。
- 更新 README、安装输出和故障排查文档。
- 检查第三方 sing-box 代码和许可证说明，确保发布方式符合其许可证要求。

## 14. 待确认但不阻塞第一阶段的问题

以下选项可先采用默认值，后续再扩展：

- 第一阶段默认入口协议：VLESS-REALITY。
- 第一阶段默认入口端口：安装时自动选择可用端口，避免占用 `8787` 和 `7928`。
- 第一阶段是否支持公网 IPv6：跟随监听地址配置，但默认同时生成 IPv4 可用配置。
- 第一阶段是否提供多入口：先单入口，数据模型预留多入口数组。
- 第一阶段是否自动配置系统防火墙：默认不自动修改，仅显示放行提示。

## 15. 预期交付物

- `singbox_manager.py`
- 更新后的 `vpngate_manager.py`
- 更新后的 `install.sh`
- 更新后的 Web UI 和 API
- 更新后的 CLI 管理命令
- 代理链配置迁移和默认配置
- 单元/集成测试或可重复验证脚本
- 更新后的 `README.md`
- 本任务文档及发布说明
