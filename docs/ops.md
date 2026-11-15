# 运维手册（v0.5.0-m4）

> 术语约定：**cocks = SOCKS5**（口语/输入错误），本文与界面统一写 SOCKS5。

---

## 1. 两种「内核更新」必须分清（P1）

| | 1A 内嵌内核升级 | 1B 远端内核升级 |
|---|---|---|
| 谁执行 | 维护者（你） | 终端用户（界面按钮） |
| 什么时候 | **构建期**，产出新 exe 前 | **运行期**，对已部署服务器 |
| 做什么 | 下载 release → 校验 sha256 → 替换 `internal/assets/kernels/` → 重新 go build | 把 **exe 内嵌的** 内核推送到远端 VPS（不联网） |
| 入口 | `./scripts/update-kernels.sh` | 界面「运维工具 → 远端内核升级」 |
| 联网 | 是（仅此时） | **否** |

**禁止**把两者做成同一个按钮；exe 运行期不得发起任何内核下载。

### 1A 用法

```bash
# 升级 xray 到 26.11.9、sing-box 到 1.14.4（amd64）
./scripts/update-kernels.sh --xray 26.11.9 --singbox 1.14.4

# 只升 xray，指定 arm64
./scripts/update-kernels.sh --xray 26.11.9 --arch arm64

# 官方没有 checksum 文件时（需人工确认）
./scripts/update-kernels.sh --xray 26.11.9 --allow-no-checksum

# 回滚上一版资源
./scripts/update-kernels.sh --rollback all

# 然后重新构建（新版本会出现在 /api/health）
./scripts/build-windows.sh && ./scripts/selfcheck.sh
```

- 备份位置：`internal/assets/kernels/<name>/<arch>.bak-<旧版本>/`
- 失败保护：下载/校验失败直接退出（非零），不写任何资源；写入用 `.tmp` + `mv` 原子替换。

### 1B 用法

界面：勾选「需更新」的行 → 选范围 → 更新选中。
接口：`POST /api/kernels/update {"server_ids":[1],"target":"all"}`

流程：读旧版本 → 传内嵌 gz → 远端 `gunzip` + `version` 自检 → 备份旧二进制 →
`install` → 再自检（版本号必须包含目标版本）→ 失败 `cp` 回滚 → `RestartAll` 重启托管服务。

手动回滚：
```bash
cp -f "$(ls -1t /usr/local/bin/xray.bak-* | head -1)" /usr/local/bin/xray
systemctl restart 'vpspanel-xray-*.service'
```

---

## 2. 自定义端口（默认 443）

- 表单不填 → 443（后端也会把 `0` 归一化成 443）；
- 校验 1–65535；越界 400；
- 占用检测只统计 **LISTEN**（出站 `->x.x.x.x:443` 不算）；
- 部署后自动 `ufw`/`firewalld` 放行，并提示 **云安全组需单独放行**；
- 同端口重复部署 = 覆盖更新（幂等），配置文件名与 unit 名都带端口。

> 兼容性提示：Reality 走 TCP 443 完全正常；**WS+TLS 复用 443 需与现有 web 服务共用端口**，
> 建议改用其它端口或加前置反代，避免与 Nginx/Apache 抢 443。

---

## 3. 前置 + 落地（统一 LandingNode）

### 3.1 落地选择列表

「落地节点」下拉把两类合并展示：
- **普通 VPS**（`servers` 表）
- **家宽 SOCKS5**（`landing_nodes` 表，状态必须为「可用」）

### 3.2 家宽 SOCKS5 录入与测试

界面「运维工具 → 落地节点」：

1. 填 名称 / 地址 / 端口（默认 1080）/ 用户名 / 密码 / 预期出口 IP（可选）；
2. 保存后点「测试」，五段验证：
   `TCP 连通 → SOCKS5 握手(RFC1928) → 用户名密码认证(RFC1929) → CONNECT 转发 → 出口 IP`
3. 预期 IP 填了就比对，不符 → 判失败且不进入可选列表；
4. 失败原因会明确区分：连不上 / 不是 SOCKS5 / 认证失败 / 无法转发 / 出口不符。

接口：
```http
GET  /api/landing-options            # 合并列表（VPS + 家宽）
GET  /api/landing-nodes              # 家宽节点列表
POST /api/landing-nodes              # 新增（密码 AES-256-GCM 加密）
POST /api/landing-nodes/:id/test     # 测试并写状态
```

### 3.3 建链路

```http
POST /api/chain/deploy
{"relay_id":1, "landing_kind":"server",     "landing_id":2, "relay_port":443, "landing_port":8443}
{"relay_id":1, "landing_kind":"home_socks5","landing_id":1, "relay_port":443}
```

统一流程（一条代码路径）：
```
落地准备(仅 server) → 前置部署 → 落地可达性 → 出口 IP 校验 → 任一步失败回滚两端
```

---

## 4. 常见故障

| 现象 | 处理 |
|---|---|
| `端口 xxx 已被占用` | 换端口，或先卸载占用该端口的节点 |
| `配置校验失败，已中止（现网未改动）` | 看日志里 xray 报错原文；现网未被修改 |
| `服务未监听端口` | 多为安全组未放行或启动失败，看 `/var/log/vpspanel-xray-<port>.log` |
| `前置无法连接落地` | 落地防火墙/安全组未放行落地端口 |
| 家宽节点「不可用」 | 看 last_error：连不上=网络/端口；握手失败=不是 SOCKS5；认证失败=账号密码 |
| `内嵌内核仅支持 x86_64` | 远端是 arm64，需维护者用 `--arch arm64` 重建 exe |

---

## 5. 目录与权限

```
/usr/local/bin/xray                       0755  内核
/usr/local/bin/xray.bak-<ts>              0755  旧内核备份（1B 自动生成）
/usr/local/etc/xray/config-<port>.json    0600  节点配置（含 UUID/私钥/家宽口令）
/usr/local/etc/xray/config-<port>.bak.<ts> 0600  配置备份
/etc/systemd/system/vpspanel-xray-<port>.service 0644
```

---

## 6. 端到端回归（`scripts/e2e.sh`）

对一个**非生产**测试机跑完整矩阵，覆盖：SSH 探测 → 7 协议部署与链接 → 同端口幂等 → 端口边界（65536/-1/abc）→ 内核版本一致性 → 自动清理。

```bash
PANEL=http://127.0.0.1:18080 SERVER_ID=1 ./scripts/e2e.sh
```

预期：`通过 11 / 失败 0`。脚本会删除本次创建的节点（端口 46001–46007），不留垃圾。

## 7. 协议状态（当前）

| 协议 | 内核 | 状态 | 说明 |
|---|---|---|---|
| VMess | xray | ✅ 可部署 | WS 传输 |
| VLESS | xray | ✅ 可部署 | Reality（默认）/ WS |
| Shadowsocks | xray | ✅ 可部署 | aes-256-gcm / chacha20 / 2022 |
| Trojan | xray | ✅ 可部署 | **自签证书**（10 年），客户端需允许不安全证书 |
| Hysteria2 | sing-box | ✅ 可部署 | QUIC/UDP，**云厂商常限 UDP** |
| SOCKS5 | xray | ✅ 可部署 | 带账号密码 |
| HTTP | xray | ✅ 可部署 | 带账号密码 |
| WireGuard | system | ✅ 可部署 | 需远端 `wireguard-tools` + 内核模块；节点"链接"位输出**客户端 INI**（WireGuard 无标准 URI） |
| MASQUE | sing-box | ⬜ 实验 | 需 sing-box endpoint 接入 |

## 8. 失败回滚与幂等（已验证）

- **坏配置**：写入 `.new.json` → 远端 `xray -test`/`sing-box check` 失败 → 删除临时文件，**现网配置字节级不变**；
- **幂等**：同端口重复部署被识别为「本面板托管 → 按更新处理」，只保留 1 份配置；
- **外部占用**：端口被非本面板进程占用时明确拒绝并给出监听者。

### WireGuard 说明

- 前置条件（面板会检测并提示）：
  ```bash
  apt install -y wireguard            # Debian/Ubuntu
  yum install -y wireguard-tools      # CentOS/RHEL
  modprobe wireguard                  # 部分精简系统需手动加载模块
  ```
- 网卡名 `wgvp<端口>`，服务端 `10.66.<端口%200>.1/24`，客户端 `.2/32`；
- 服务端配置写入 `/etc/wireguard/wgvp<端口>.conf`（0600），含 `PostUp` 的 NAT 规则（自动探测默认出口网卡）；
- 部署成功后，面板在「节点链接」处给出**客户端 INI**，可直接导入 WireGuard 官方客户端；
- 卸载：`wg-quick down wgvp<端口>` 并删除配置（面板「卸载」按钮已覆盖）。

---

## 9. 面板测试的凭据安全（v0.9.1 起）

- SOCKS5 / HTTP 节点的账号密码**不再出现在远端命令行**（否则 `ps aux` 可看到）；
- 改为写入 `/tmp/vp-curl-<节点ID>.conf`（0600），用 `curl -K <文件>` 引用，测完立即删除；
- 其它协议走本地临时客户端（127.0.0.1 无凭据 SOCKS 入口），命令行不含任何密钥；
- 同一节点的测试串行执行（`serverID:port` 锁），避免临时文件互相覆盖。

---

## 10. 非 root 用户部署（v1.1.0 起）

面板支持用普通用户（如 `next`）登录，但写 `/usr/local/bin`、`/usr/local/etc`、`/etc/systemd/system` 需要 root：

| 场景 | 行为 |
|---|---|
| 用 root 登录 | 直接执行 |
| 普通用户 + **免密 sudo** | 自动给系统命令加 `sudo -n` 前缀 |
| 普通用户 + 无免密 sudo | **上传前即失败**，日志明确提示：「当前用户 X 无 root 权限，且缺少 sudo 免密配置」并给出三种解决办法 |

配置免密 sudo（推荐最小权限）：

```bash
echo 'next ALL=(ALL) NOPASSWD: /usr/bin/install, /usr/bin/cp, /usr/bin/mv, /usr/bin/chmod, /bin/systemctl, /usr/bin/pkill' \
  | sudo tee /etc/sudoers.d/vpspanel
sudo chmod 440 /etc/sudoers.d/vpspanel
```

**内核安装流程（每一步的 stdout/stderr 都会回传前端日志）**：

```
→ 推送内嵌 xray v26.11.9（约 13 MB）
  推送中 25% / 50% / 75% / 100%
✓ 已上传: /tmp/xray_upload.gz
$ gunzip -f -c /tmp/xray_upload.gz > /tmp/xray_upload && chmod 0755 /tmp/xray_upload && /tmp/xray_upload version 2>&1 | head -3
  Xray 26.11.9 ...
✓ 内核校验通过（26.11.9）
✓ 已备份旧内核 → /usr/local/bin/xray.bak-20261115-101010
✓ 已安装到 /usr/local/bin/xray
✓ xray v26.11.9 校验通过
```

失败时会给出**可读原因**（不再只说「安装失败，已回滚」）：

| 原始输出 | 前端显示 |
|---|---|
| `Permission denied` | 权限不足（Permission denied），当前用户无法写入系统路径 |
| `command not found` | 命令不存在（command not found），目标机可能缺少基础工具 |
| `Exec format error` | 内核架构与目标机不符或文件损坏（Exec format error） |
| `sudo: a terminal is required` | 缺少 sudo 免密（sudo 要求输入密码或终端） |
| `Text file busy` | 内核文件正被占用，请先停止该节点服务 |
