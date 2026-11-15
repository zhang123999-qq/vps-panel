## 10. # VpsPanel 架构说明（对应代码 v1.1.1）

> 状态：方案评审中（未开始编码）
> 日期：2026-11-15

## 0. 已确认约束（2026-11-15）

| 项 | 决定 | 影响 |
|---|---|---|
| 使用场景 | **个人自用** | 不做多租户、不做计费；权限系统降级到 P2（甚至可以砍掉） |
| 规模 | **约 10 台 VPS** | **SQLite 足够**，不需要 PostgreSQL；无需连接池调优 |
| 并发 | 部署任务上限 **3/批** | 避免同时打满多个 SSH 会话被服务商限速 |
| 巡检 | 每 5 分钟 / 每台，10 台共 10 个轻量 SSH 命令 | 开销可忽略 |
| 备份 | `data/` 目录整体打包即可（DB + 主密钥 + 日志） | 不需要专业备份方案 |
| 交付形态 | **绿色单文件 exe，双击即用，零安装零下载** | 前端与内核全部内嵌；保留控制台窗口；数据写 exe 同级 `data/` |
| 协议范围 | 目标 9 种；**已实现 8 种**（VMess / VLESS / Shadowsocks / Trojan / Hysteria2 / WireGuard / SOCKS / HTTP），MASQUE 待接（界面标 experimental） | xray + sing-box 双内核都已内嵌 |
| sing-box | 「先不做」指**不做 sing-box 协议族/独立入口**，但 Hysteria2 与 MASQUE 必须借它 | 内核内嵌，界面只暴露协议，不暴露内核 |

**由此简化掉的**：多用户/RBAC、套餐计费、分布式任务队列（Redis）、读写分离。
**仍然保留的**：凭证加密、审计日志、二次确认、实时部署日志、失败回滚。

---

## 1. 目标与非目标

### 目标
1. **VPS 资产管理**：增删改查、分组、标签、到期提醒、SSH 连通性巡检。
2. **一键部署节点**：选中若干 VPS → 选择协议模板 → 批量下发 xray / sing-box → 实时看日志 → 回滚。
3. **统一链接输出**：每个节点可一键复制标准 URI（v2rayN / sing-box 可直接导入）；**不做订阅分发**。
4. **运行状态与流量**：节点存活、CPU/内存/磁盘、按用户或节点的流量统计。

### 非目标（v1 不做）
- 不做"机场"式计费、套餐、分销系统。
- 不做自建 CDN / 中转链路编排。
- 不做移动端 App（先做响应式 Web）。

---

## 2. 先想清楚：自研 vs 用现成

| 方案 | 定位 | 局限 |
|---|---|---|
| **3x-ui / x-ui** | 单机面板，管 xray 入站与用户 | 一台机器一个面板，管 10 台 VPS 要开 10 个后台 |
| **Marzban** | 单机节点 + 用户/流量管理 + 订阅 | 同样是一机一装，无跨机资产视图 |
| **Hiddify** | 多协议一体化 | 偏单机，二次开发成本高 |
| **自研（本项目）** | **一个后台管 N 台机器** | 开发量大，需自己做部署引擎与容错 |

**结论**：自研的真实价值只有一个——**"上帝视角"**。一台面板看到所有 VPS、所有节点、所有流量，批量下发、批量巡检、统一导出链接。
如果只是想单机搭节点，不必自研，直接用 3x-ui。**这个前提需要你确认。**

---

## 3. 功能清单（按优先级）

### P0 — MVP（能用）
- [x] 登录：**不做**——定位为本地单用户工具，改用「Host / Origin / Content-Type」三重来源校验（`SecurityGuard`）
- [ ] VPS 列表 / 新增 / 编辑 / 删除
- [ ] SSH 连通测试 + 采集系统信息（OS、内核、CPU、内存、磁盘、已装节点）
- [ ] 协议模板管理（VLESS+Reality、Hysteria2 起步）
- [ ] 一键部署：上传二进制 + 写配置 + systemd + 防火墙 + 启动
- [ ] 部署日志实时回传（WebSocket）
- [ ] 节点启停 / 重载 / 卸载 / 配置回滚
- [x] 分享链接（单节点复制，不做订阅）

### P1 — 好用
- [ ] 批量操作（多选 VPS 一起部署/巡检/重启）
- [x] **不做订阅分发**：仅提供「单节点复制链接」（v2rayN / sing-box 客户端可直接导入）
- [ ] 流量与在线统计（xray stats API / sing-box Clash API）
- [ ] 定时巡检 + 掉线告警（Webhook / 邮件）
- [ ] 到期提醒（VPS 续费日）
- [ ] 审计日志

### P2 — 完善
- [ ] 多用户 + 角色（管理员 / 只读）
- [ ] 2FA（TOTP）
- [ ] 证书自动签发（acme.sh / Let's Encrypt）与自动续期
- [ ] 配置模板可视化编辑 + 校验
- [ ] 快照：部署前自动备份原配置，一键还原

---

## 4. 技术选型

### 推荐栈：Go + Vue 3

| 层 | 选型 | 理由 |
|---|---|---|
| 后端 | **Go 1.22 + Gin + GORM** | SSH 并发天然强；`go:embed` 可把前端打进单二进制；交叉编译到 Linux 一条命令；部署零依赖 |
| SSH | `golang.org/x/crypto/ssh` | 纯 Go，支持密码/私钥/跳板，可复用连接池 |
| 前端 | **Vue 3 + Vite + Element Plus + Pinia** | 管理后台生态成熟，表格/表单/弹窗现成，中文文档全 |
| 数据库 | **SQLite**（默认）→ **PostgreSQL**（多人时迁移） | 单机自用零运维；GORM 切换只需改 DSN |
| 实时日志 | WebSocket 推送 | 部署过程需要流式输出，SSE 也可 |
| 任务 | DB 表 + goroutine worker pool | MVP 不引 Redis，减少部署复杂度 |
| 部署 | 单二进制 + 可选 Docker Compose | 一个文件丢上去就能跑 |

### 备选栈（如果你更熟别的）
- **Python + FastAPI + Vue**：开发快，但需要 venv/依赖管理，`paramiko` 并发弱于 Go。
- **Node + NestJS + Vue**：全 TS 一套语言，`ssh2` 库可用，但内存占用高、单文件部署难。

> **建议**：这项目的核心难点在「远程执行 + 幂等 + 容错」，Go 的并发和单文件部署能省掉大量运维麻烦。但**如果你以后要自己维护**，选你最熟的语言更重要。

---

## 5. 系统架构

```
┌───────────────────────────────────────────────┐
│  浏览器 (Vue3 SPA)                             │
│  资产表格 / 部署向导 / 实时日志 / 订阅          │
└───────────────┬───────────────────────────────┘
                │ REST + WebSocket
┌───────────────▼───────────────────────────────┐
│  Go 单体服务                                   │
│  ┌─────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ API 层  │ │ 任务调度 │ │ 部署引擎       │  │
│  │ 鉴权    │ │ worker池 │ │ provisioning   │  │
│  │ 审计    │ │ 重试     │ │ 幂等/回滚      │  │
│  └────┬────┘ └────┬─────┘ └───────┬───────┘  │
│       │           │              │           │
│  ┌────▼───────────▼──────────────▼───────┐   │
│  │ SSH 连接池 (x/crypto/ssh)              │   │
│  │ 密码/私钥 · 跳板 · 超时 · 并发限制     │   │
│  └────────────────┬───────────────────────┘   │
│  ┌────────────────▼──────────┐ ┌───────────┐ │
│  │ 指标采集 (stats API/gRPC) │ │ SQLite    │ │
│  └───────────────────────────┘ └───────────┘ │
└───────────────┬───────────────────────────────┘
                │ SSH (22) / HTTPS API
     ┌──────────▼──────────┐   ┌─────────────────┐
     │ VPS #1  xray         │   │ VPS #N  sing-box │
     │ systemd + config     │   │ systemd + config │
     └─────────────────────┘   └─────────────────┘
```

### 部署引擎（最关键的部分）

**设计原则：不 `curl | bash`，不依赖第三方安装脚本。**

每一步都显式可控：

```
1. 预检   ：uname -m 判架构(x86_64/aarch64)、检查 80/443/端口占用、检查 systemd、磁盘余量
2. 传文件 ：SFTP 上传 xray-core / sing-box 官方发布包 → 解压 → /usr/local/bin/
3. 写配置 ：模板渲染 config.json（含 UUID/密钥/端口/SNI），先写 xxx.json.new
4. 校验   ：远程执行 `xray -test -c xxx.json.new` / `sing-box check -c ...`
5. 备份   ：现网配置 → /etc/xxx/backup/<时间戳>/
6. 切换   ：mv .new → 正式路径；systemctl enable && restart
7. 验活   ：ss -lntp 看端口在听；systemctl is-active；本地 TCP 探测
8. 防火墙 ：ufw/firewalld 放行端口（仅放实际需要的）
9. 收尾   ：写元数据（协议/端口/密钥指纹）回数据库；日志归档
```

失败点处理：
- 第 2–4 步失败 → 直接中止，机器上什么都没变；
- 第 6 步失败 → 自动从备份还原 + 重启旧服务；
- 第 7 步失败 → 标记「部署异常」，保留日志供排查，不回滚（方便看现场）。

**幂等性**：同一 VPS 重复部署同协议 = 更新配置 + 重启，不会产生重复服务/重复端口。

### 协议 × 内核矩阵（目标 9 种，已实现 8 种）

| 8 | SOCKS5 | xray | 不需要 | TCP | ★ | ✅ 已实现 |
| 9 | HTTP 代理 | xray | 不需要 | TCP | ★ | ✅ 已实现 |

**实现状态**：1–9 中除 **MASQUE（#7）** 外全部可部署；MASQUE 需 sing-box endpoint，
当前在界面上标为「实验」且不会假报成功。

> 结论：**xray 与 sing-box 两个内核都必须内嵌**。Hysteria2 和 MASQUE 只有 sing-box 支持，无法用 xray 替代。
> 但界面上不暴露「内核」概念，用户只选协议。

| # | 协议 | 内核 | 要域名/证书 | 传输 | 难度 |
|---|---|---|---|---|---|
| 1 | **VMess**(AEAD) | xray | WS+TLS 时需要 | TCP/WS | ★ |
| 2 | **VLESS**(Reality / WS+TLS / gRPC) | xray | Reality 不需要 | TCP | ★★ |
| 3 | **Shadowsocks**(2022) | xray | 不需要 | TCP/UDP | ★ |
| 4 | **Trojan** | xray | 需要（可自签） | TCP | ★ |
| 5 | **Hysteria2** | **sing-box** | 需要（可自签） | QUIC/UDP | ★★★ |
| 6 | **WireGuard** | 系统 `wg-quick` | 不需要 | UDP | ★★ |
| 7 | **MASQUE**(CONNECT-IP) | **sing-box** endpoint | 需要 TLS | HTTP/3 | ★★★★ |
| 8 | **SOCKS5** | xray | 不需要 | TCP | ★ |
| 9 | **HTTP 代理** | xray | 不需要 | TCP | ★ |

实现取舍：
- **WireGuard 优先用系统 `wg-quick`**（内核态、性能好），失败回退 xray userspace inbound；
- **MASQUE 用 sing-box 的 endpoint `masque-server`**，需 sing-box ≥ 1.14，界面标注「实验」；
- 单台 VPS 可同时部署多协议：多实例 + 多端口，配置目录按 `协议-端口` 隔离。

### 内嵌内核（零下载的关键）

```
internal/kernel/embed/
  xray-linux-amd64.zip         16.7 MB   (Xray v26.11.9)
  sing-box-linux-amd64.tar.gz  31.7 MB   (sing-box v1.14.4)
```

- `go:embed` 打包，部署时解压上传到远端 `/usr/local/bin/`；
- 版本在 `internal/kernel/version.go` 锁定，可复现、不受上游删包影响；
- **待确认**：是否有 ARM 架构 VPS（Oracle 免费机常见）——有的话再加 arm64 两包，exe 体积约翻倍到 140MB。

---

## 6. 数据模型

```
users          id, username, password_hash(argon2id), role, totp_secret, created_at
servers        id, name, host, ssh_port, ssh_user, auth_type, secret_cipher,
               tags, provider, region, expires_at, status, last_check_at,
               os_info(json), cpu_cores, mem_mb, disk_gb, note
templates      id, name, core(xray|sing-box), protocol, config_tmpl, defaults(json)
deployments    id, server_id, template_id, protocol, port, config_json,
               status, version, prev_backup_path, created_by, created_at
subscriptions  id, name, token(随机32位), filter(json), format, enabled
metrics        id, server_id, ts, cpu, mem, disk, net_in, net_out, uptime
traffic        id, server_id, user_tag, up_bytes, down_bytes, sampled_at
tasks          id, type, target_id, status, progress, log_path, created_at
audit_logs     id, user_id, action, target, payload(json), ip, created_at
```

**凭证存储**：SSH 密码/私钥用 **AES-256-GCM** 加密后入库，主密钥 `MASTER_KEY` 只放环境变量或 `./data/master.key`（0600）。数据库被拿走也无法直接解密。

---

## 7. 安全设计（这部分不能省）

| 面 | 措施 |
|---|---|
| 面板访问 | 仅监听 `127.0.0.1`；`SecurityGuard` 校验 Host（挡 DNS rebinding）、写请求 Content-Type（挡表单 CSRF）、Origin 同源 |
| 面板暴露 | **默认只监听 127.0.0.1**，前面挂 Nginx + TLS；或走 Cloudflare Tunnel / WireGuard，不直接开公网 |
| 远程命令 | 一律**白名单化的固定脚本**，参数做 shell 转义；禁止把用户输入拼进命令行 |
| 凭证 | AES-GCM 加密 + 主密钥外置 + 日志脱敏（不打印私钥/密码） |
| 危险操作 | 删除 VPS、卸载节点、批量重启 → 二次确认 + 操作摘要 |
| 审计 | 所有写操作落 `audit_logs`，记录谁、何时、对哪台、做了什么 |
| SSH | 优先密钥登录；执行用户最好非 root（sudo 白名单），降低面板被攻破后的爆炸半径 |
| 速率 | 部署任务并发上限（默认 3/批），避免把自己机器 SSH 打满或被服务商限速 |

---

## 8. 交付形态（已确认：绿色单文件 exe，零安装）

**不安装、不下载、不要运行库 —— 双击 `VpsPanel.exe` 就开始用。**

```
双击 VpsPanel.exe
  ↓ 弹出命令行窗口（显示启动状态与访问地址）
  ↓ 自动打开默认浏览器 http://127.0.0.1:18080
  ↓ 浏览器里做所有操作（增删改查 / 一键部署 / 看日志）
  ↓ 关闭命令行窗口 = 退出程序
```

数据目录（**优先便携，其次用户目录**）：
```
① exe 同级 ./data/        ← 可写就用这个（U盘/绿色版友好）
② 不可写则回退 %LOCALAPPDATA%\VpsPanel\
   ├── vpspanel.db     SQLite (WAL)
   ├── vpspanel.log     日志
   └── master.key       AES 主密钥 (0600)
```

要点：
- **保留控制台窗口**（构建不加 `-H windowsgui`），用户能看到「服务已启动 + 地址 + 日志」；
- 前端全部 `go:embed` 打进 exe，**不需要任何外部文件**；
- 代理内核（xray / sing-box 的 linux 二进制）同样内嵌，**部署时不联网下载**；
- exe 体积预估 **约 70–80MB**，这是"零依赖"的代价，可接受；
- 升级 = 用新 exe 覆盖旧 exe，数据在 `data/` 里不受影响。

## 8.1 链接输出（已确认：不做订阅）

定位为本地自用工具，**不生成订阅、不做分发**。节点详情页提供「复制链接」，输出标准 URI：

| 协议 | 形式 |
|---|---|
| VMess | `vmess://base64(JSON)` |
| VLESS | `vless://uuid@host:port?security=reality&pbk=…&sid=…` |
| Shadowsocks | `ss://base64url(method:password)@host:port` |
| Trojan | `trojan://password@host:port?security=tls&allowInsecure=1` |
| Hysteria2 | `hysteria2://password@host:port/?sni=…&insecure=1` |
| SOCKS5 / HTTP | `socks://` / `http://` + base64url 账号 |
| WireGuard | 无标准 URI → 直接给**客户端 INI** |

密码类字段统一用 `url.User` 编码（空格 → `%20`，避免 `+` 被当成字面加号）。

## 9.实际进度）

| 阶段 | 内容 | 状态 |
|---|---|---|
| M0 | 骨架 / DB / 静态托管 / 交叉编译 | ✅ |
| M1 | VPS CRUD、SSH 探测、凭证加密、审计 | ✅ |
| M2a | 部署引擎（xray 5 协议）+ 9 步日志 + 回滚 | ✅ |
| M2b | 内核双层升级（1A 构建期 / 1B 运行时） | ✅ |
| M2c | 端口默认 443、前置+落地链路、家宽 SOCKS5 | ✅ |
| M2d | LandingNode 统一抽象 | ✅ |
| M2e | Trojan（自签 TLS）、Hysteria2（sing-box） | ✅ |
| M2f | WireGuard（wg-quick） | ✅ |
| M2g | MASQUE（sing-box endpoint） | ⬜ |
| M3 | 本地效能：复制链接、面板测速、清理残余 | ✅ |
| M4 | 数据库迁移机制 / 单实例 / 安全加固 / CI 脚本 | ✅ |

## 10. 早期待确认问题的最终答案

| 早期问题 | 最终决定 |
|---|---|
| 自用还是多人？ | **个人自用**，约 10 台 → SQLite（WAL），单用户，不做权限系统 |
| 技术栈？ | **Go + 原生 JS 单页**（`go:embed` 内嵌），不引前端框架与 CDN |
| 订阅格式？ | **不做全局订阅**，只做「单节点复制链接」，v2rayN 可直接导入 |
| 面板放哪？ | **本机 Windows 绿色单 exe**，仅监听 `127.0.0.1`，双击启动 |
| 是否要 UDP 协议？ | **要**（Hysteria2 / WireGuard），需注意云厂商限 UDP |
| 规模？ | 约 10 台，SQLite + WAL + 单实例锁足够 |
| 合规？ | 仅在自有或明确授权的 VPS 上操作，遵守服务商 ToS 与当地法律 |

---

## 11. 内核版本策略（P1）与落地抽象（P2）

### 11.1 内核：对内可升级，对外锁死

| 层 | 入口 | 时机 | 是否联网 |
|---|---|---|---|
| **1A 内嵌内核升级** | `scripts/update-kernels.sh`（维护者专用） | **构建期** | 是（下载 release + 校验 sha256） |
| **1B 远端内核升级** | 界面「运维工具 → 远端内核升级」 | **运行期** | 否，推送的是 exe 内嵌的二进制 |

- 资源目录：`internal/assets/kernels/{xray,singbox}/<arch>/{*.gz, version.txt}`；
- 版本唯一来源：`internal/assets` 的 `version.txt` → `kernel.XrayVersion / SingboxVersion`；
- 三处必须一致：`/api/health` 的 `kernels` 字段、启动日志 `内嵌内核: xray … / sing-box …`、本文档；
- `1A` 备份到 `internal/assets/kernels/<name>/<arch>.bak-<旧版本>/`，`--rollback` 可恢复；
- **exe 运行时不得任何下载**：`internal/kernel` 只做「读内嵌 → 上传远端」，无 HTTP 客户端。

### 11.2 落地统一抽象（P2）

```
landing.Node
 ├─ KindServer      : 普通 VPS，按协议生成入站(xray)，前置用对应 outbound
 └─ KindHomeSocks5  : 家宽 SOCKS5，不部署落地，前置直接 socks outbound
```

- `chain.Deploy` 只有**一条流程**：落地准备（按 kind 分支）→ 前置部署 → 可达性 → 出口 IP 校验 → 失败回滚两端；
- 新增落地类型 = 在 `landing.Node.Outbound/Reachable/ExitIP/Inbound` 加分支，**不新增流程**；
- 家宽节点存在 `landing_nodes` 表（地址/端口/用户名/AES 密码/预期出口 IP/测试状态），
  `/api/landing-options` 把「VPS + 家宽」合并成一个列表给前端选。
