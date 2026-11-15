# VpsPanel

本地运行的 VPS 集中管理与节点一键部署工具。**个人自用、约 10 台 VPS。**

- 形态：**绿色单文件 exe**，双击启动 → 命令行窗口 → 自动打开浏览器；零安装、零下载
- 后端：Go + Gin + GORM + SQLite（纯 Go 驱动，无 CGO 依赖，可交叉编译）
- 前端：原生 JS 单页（内嵌进 exe）
- 内核：xray 26.11.9 + sing-box 1.14.4（均内嵌，运行期不联网）
- 协议：**8 种可部署**（VMess / VLESS / Shadowsocks / Trojan / Hysteria2 / WireGuard / SOCKS5 / HTTP）
  　　+ 1 种实验（MASQUE，界面标 experimental，不假装可用）
  　　WireGuard 需远端已装 `wireguard-tools` 且内核支持（面板会给出安装命令）

## 进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| M0 | 项目骨架 / DB 迁移 / 静态托管 / 交叉编译 | ✅ |
| M1 | VPS CRUD + SSH 探测 + 凭证加密（AES-256-GCM）+ 审计日志 | ✅（单用户本地，无登录） |
| M2a | 部署引擎 + xray 五协议 + 实时日志 + 回滚 | ✅ |
| M2b | 内核一键更新（xray + sing-box，含备份/校验/回滚） | ✅ |
| M2c | 自定义端口（默认 443）、前置+落地链路、家宽 SOCKS5 落地 | ✅ |
| M2d | P1 内核双层升级（1A 构建期脚本 / 1B 运行时推送）、P2 LandingNode 统一抽象 | ✅ |
| M2e | Trojan（自签 TLS）+ Hysteria2（sing-box/QUIC）接入、通用安装器去重、E2E 回归脚本 | ✅ |
| M2f | WireGuard 接入（wg-quick + 客户端 INI 输出） | ✅ |
| M2g | MASQUE（sing-box endpoint） | ⬜ |
| M3 | 订阅导出（v2rayN / sing-box JSON） | ⬜ |
| M4 | 流量统计 / 定时巡检 / 到期提醒 | ⬜ |

## 功能一览

**资产**
- VPS 增删改查、SSH 密码/私钥认证、AES-256-GCM 加密存储
- 连接测试 + 系统信息（OS/内核/核数/内存/磁盘）自动采集

**部署**
- 一键部署：VLESS+Reality、VLESS+WS、VMess+WS、Shadowsocks、SOCKS5、HTTP
- 端口默认 **443**，支持自定义；越界校验、LISTEN 占用检测、防火墙自动放行与云安全组提示
- 部署九步：架构 → 端口 → 内核 → 参数 → 配置 → 远端校验 → 备份 → 启动 → 验活
- 节点详情：协议 / 端口 / 状态 / 原始链接（点击复制）/ 卸载

**运维**
- **内核双层升级**（严格区分）
  - 1A 内嵌内核升级：`scripts/update-kernels.sh`（构建期，校验 sha256，支持 `--rollback`）
  - 1B 远端内核升级：界面推送内嵌内核到远端（运行期**不联网**），带版本差异表/备份/自检/回滚/自动重启
- **前置 + 落地链路**：落地统一抽象 `landing.Node`（VPS 或家宽 SOCKS5），一条流程跑完
  落地部署 → 前置部署 → 可达性 → 出口 IP 校验，任一步失败回滚两端
- **落地节点（家宽 SOCKS5）**：TCP → 握手 → 认证 → CONNECT → 出口 IP 五段测试，通过后直接可选为落地

## 快速开始

```bash
# 开发运行
VPSPANEL_NO_BROWSER=1 go run ./cmd/vps-panel

# Windows 打包
./scripts/build-windows.sh            # 产物 dist/VpsPanel.exe

# 一条命令跑完所有质量门（gofmt / vet / 单测 / 双平台编译 / 敏感信息）
./scripts/ci.sh
E2E=1 PANEL=http://127.0.0.1:18080 SERVER_ID=1 ./scripts/ci.sh   # 追加端到端

# 仅自检（同上但更轻）
./scripts/selfcheck.sh

# 端到端回归（对已登记的测试 VPS 跑 7 协议矩阵 + 边界 + 幂等 + 清理）
PANEL=http://127.0.0.1:18080 SERVER_ID=1 ./scripts/e2e.sh

# 1A：升级内嵌内核并重建 exe（仅维护者构建期使用）
./scripts/update-kernels.sh --xray 26.11.9 --singbox 1.14.4
./scripts/update-kernels.sh --rollback all
```

数据目录（优先 exe 同级 `./data`，不可写则回退用户目录）：
Windows `%LOCALAPPDATA%\VpsPanel\` · Linux/macOS `~/.local/share/vpspanel/`

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| GET/POST/PUT/DELETE | `/api/servers[/:id]` | 服务器 CRUD |
| POST | `/api/servers/:id/test` | 连通测试 + 信息采集 |
| POST | `/api/probe` | 表单内「测试连接」（不落库） |
| GET | `/api/servers/:id/nodes` | 已部署节点 |
| POST | `/api/deploy` | 部署单协议 |
| DELETE | `/api/deployments/:id` | 卸载节点 |
| POST | `/api/deployments/:id/test` | **本地面板测试**：真实出口 IP + 延迟 |
| POST | `/api/servers/:id/cleanup` | **清理残余**：停止并删除本面板节点服务/配置 |
| GET | `/api/kernels` | 内嵌版本 + 各远端版本差异 |
| POST | `/api/kernels/update` | 1B 远端内核推送 |
| GET | `/api/landing-options` | 落地候选（VPS + 家宽合并） |
| GET/POST/PUT/DELETE | `/api/landing-nodes[/:id]` | 家宽 SOCKS5 节点管理 |
| POST | `/api/landing-nodes/:id/test` | 家宽节点五段测试 |
| POST | `/api/chain/deploy` | 前置 + 落地链路（kind=server/home_socks5） |
| GET | `/api/audit` | 审计日志 |

## 内嵌内核与体积

| 资源 | 大小 |
|---|---|
| `xray.gz` (26.11.9, amd64) | 13 MB |
| `sing-box.gz` (1.14.4, amd64) | 27 MB |
| exe（含前端与双内核） | **约 70 MB** |

版本唯一来源：`internal/assets/kernels/*/amd64/version.txt` → `/api/health` 的 `kernels` 字段、
启动日志 `内嵌内核: xray … / sing-box …`、本文档三处一致。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | 架构、协议矩阵、内核版本策略、落地抽象、里程碑 |
| [`docs/ops.md`](docs/ops.md) | 运维手册：内核升级、链路、家宽、非 root 部署、本地效能、回滚 |
| [`docs/AUDIT.md`](docs/AUDIT.md) | 审计与测试报告：P0×4 / P1×18 / P2×8、测试矩阵与证据 |
| [`CHANGELOG.md`](CHANGELOG.md) | 版本变更记录（v0.1.0 → v1.1.1） |
| [`LICENSE`](LICENSE) | 开源许可证（MIT） |
| [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) | 内嵌内核（MPL-2.0 / GPL-3.0）与依赖的许可证义务 |
| [`dist/使用说明.txt`](dist/使用说明.txt) | 面向使用者的操作说明 |

## 安全约定

- 面板只监听 `127.0.0.1`，不对外暴露；
- SSH 凭证 / 引用密码用 AES-256-GCM 加密入库，主密钥 `master.key` 权限 0600；
- 远端配置含密钥，写入权限 0600；
- 主机字段做字符白名单校验，远端命令不接受拼接的用户输入；
- 同一台机器的同一端口部署加互斥锁，避免并发写坏配置；
- 所有写操作写审计日志。

## 许可证

自有代码以 **MIT** 发布（见 [`LICENSE`](LICENSE)）。

内嵌内核**不在 MIT 范围内**：

| 组件 | 许可证 | 说明 |
|---|---|---|
| Xray-core 26.11.9 | **MPL-2.0** | 原样分发二进制，未修改源码 |
| sing-box 1.14.4 | **GPL-3.0** | 对外分发含 sing-box 的 exe 需遵守 GPLv3（提供源码或书面要约） |

仅自用（自己编译、部署到自己的 VPS）不触发分发义务；对外分发的注意事项与替代方案见
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

## 回滚速查

```bash
# 内核回滚
cp -f "$(ls -1t /usr/local/bin/xray.bak-* | head -1)" /usr/local/bin/xray
systemctl restart 'vpspanel-xray-*.service'   # 无 systemd 时 pkill + nohup 重启

# 配置回滚（部署时自动备份）
cp -f /usr/local/etc/xray/config-443.json.bak.<时间戳> /usr/local/etc/xray/config-443.json
systemctl restart vpspanel-xray-443.service
```
