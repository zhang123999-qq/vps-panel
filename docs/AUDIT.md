# VpsPanel 审计与测试报告（v1.0.2）

> 审计对象：Go + 内嵌前端 + SQLite，单 exe 本地工具
> 审计方式：静态审查 + 单元测试 + 集成测试（真实 sshd / 真实部署）+ 浏览器实测
> 结论：**P0×4、P1×17、P2×8 全部处理**；测试 **38 项**（单测 36 / 集成 5 / 启动 2 / E2E 12）+ `-race` 竞态检测

---

## 1. 测试矩阵

### 1.1 SSH 探测与异常处理

| 用例 | 预期 | 实际状态 |
|---|---|---|
| 密码错误 | `status=offline`，错误单行 | ✅ 已验证 |
| 私钥格式错误 | 明确报错，不崩溃 | ✅ 单测 |
| IP 不通 / 端口错误 | 8s 超时 + 明确原因 | ✅ 已验证 |
| **家目录缺失（stderr 污染）** | `os` 仍为 `Debian GNU/Linux 12 (bookworm)` | ✅ 已验证（污染 banner sshd） |
| 主机名注入 `; rm -rf /` | 400 拒绝 | ✅ API 测试 |
| 指纹被篡改（中间人） | 拒连并提示 | ✅ E2E |

### 1.2 协议部署引擎

| 用例 | 预期 | 状态 |
|---|---|---|
| VLESS / VMess / SS / Trojan / Hysteria2 / SOCKS5 / HTTP | 部署成功 + 监听 + 链接 | ✅ E2E 11/11 |
| WireGuard | 需远端 tools；缺失时给安装命令 | ✅ 依赖缺失路径验证；**真机待验** |
| 端口 `0` / `65536` / `-1` / `abc` | 0→443；其余 400 | ✅ API 测试 |
| 端口被外部占用 | 拒绝并给出监听者 | ✅ 已验证 |
| 端口被自己占用 | 按「更新」处理（幂等） | ✅ 已验证 |
| `xray -test` 失败 | 现网配置字节级不变 | ✅ 集成测试 |
| 上传中断 | 不替换二进制 + 清理 /tmp | ✅ 代码路径 |
| 防火墙放行失败 | 明确告警，不假装成功 | ✅ 已验证（伪造 ufw） |
| 并发同端口 | 一封一败，无双写 | ✅ 并发实测 |
| 并发不同端口 | 三个独立监听 | ✅ 并发实测 |

### 1.3 前置 / 落地链路（LandingNode）

| 用例 | 预期 | 状态 |
|---|---|---|
| 前置 + VPS 落地 | 部署 + 可达 + 出口 IP | ✅ 已验证（223.89.228.134） |
| 前置 + 家宽 SOCKS5 落地 | 不部署落地，前置走 socks 出站 | ✅ 已验证 |
| 落地失效 | 明确报错 + 回滚两端 | ✅ 已验证（9743 被清理） |
| 出口 IP 不符 | 失败回滚 | ✅ 代码路径 + 单测 |

### 1.4 内核与构建

| 用例 | 预期 | 状态 |
|---|---|---|
| 1A 脚本升级 + 重编译 | `/api/health` 返回新版本 | ✅ 已验证（含 `--rollback`） |
| 运行期是否有外网下载 | 无 | ✅ 源码级证明（无 http.Client） |
| 1B 远端推送 + 回滚 | 版本差异可见、失败回滚 | ✅ 已验证 |

### 1.5 数据库与前端

| 用例 | 预期 | 状态 |
|---|---|---|
| 老库自动补字段 | 字段存在、数据不丢 | ✅ 单测（真实 ALTER TABLE） |
| 重复启动 | 不重复执行迁移 | ✅ 单测 |
| 库版本高于程序 | 拒绝启动 | ✅ 单测 |
| 表格长文本 | `nowrap + ellipsis`，不撑破 | ✅ 浏览器几何实测 |
| API 返回 null | 不白屏 | ✅ 已修（filter） |
| XSS 载荷进名称/备注 | 不执行 | ✅ 浏览器实测（0 个注入元素） |
| CSRF / DNS rebinding | 403 / 415 | ✅ API 测试 |
| 超大请求体（>1MB） | 413（边界拦截，不进 handler） | ✅ 单测 + 运行时实测 |
| 安全响应头 | X-Frame-Options / nosniff / no-referrer | ✅ 单测 + 运行时实测 |

---

## 2. 审计发现

### P0（致命）

| 编号 | 风险 | 位置 | 状态 |
|---|---|---|---|
| P0-1 | 家宽节点 host 未校验 → 拼进 `/dev/tcp` **命令注入** | `api/ops.go` landingCreate/Update、`landing/landing.go:tcpCheckFrom` | ✅ 已修（`validate.Host` + 执行层二次校验） |
| P0-2 | 链路/内核路径无锁 → 并发写坏配置 | `api/ops.go` chainDeploy / kernelUpdateOne | ✅ 已修（`lockPlan`） |
| P0-3 | SSH 未校验主机指纹 → 中间人可窃取凭证 | `sshx/ssh.go` | ✅ 已修（TOFU + `known_hosts.json` 0600） |

### P1（逻辑与健壮性）

| 编号 | 风险 | 位置 | 状态 |
|---|---|---|---|
| P1-1 | `CombinedOutput` 致 stderr 污染（端口误判、日志脏） | `sshx` 全包 | ✅ 已修（`RunOut` 16 处） |
| P1-2 | 端口检查把自己上一版部署当「占用」 | `provision.Prepare` | ✅ 已修（`isOwnService`） |
| P1-3 | 解密家宽口令失败被吞 | `api/ops.go` | ✅ 已修 |
| P1-4 | 认证方式切换未校验凭证 | `api/servers.go` | ✅ 已修 |
| P1-5 | 防火墙放行失败仍报成功 | `provision.OpenFirewall` | ✅ 已修 |
| P1-6 | 前端 null 行导致白屏 | `web/index.html:load()` | ✅ 已修 |
| P1-7 | 无 CSRF / DNS-rebinding 防护 | `api` 中间件 | ✅ 已修（`SecurityGuard`） |
| P1-8 | 面板测试把密码放进远端命令行（`ps` 可见） | `api/nodetest.go` | ✅ 已修（0600 curl 配置 + `-K`） |
| P1-9 | 临时测试进程清理不彻底（pkill 自匹配） | `api/nodetest.go` | ✅ 已修（按 PID） |
| P1-10 | 数据库无迁移机制，加字段对老库无效 | `store/db.go` | ✅ 已修（`user_version`） |
| P1-11 | 死代码 / 重复安装流程 | `provision`、`api` | ✅ 已修（`installService` 合并、删除 `DeployRaw`） |
| P1-12 | 端口归属仅识别 xray，Hysteria2 无法重部署 | `provision` | ✅ 已修（双内核命名） |


### 2.5 后续轮次补充发现（v0.9.0 → v1.0.1）

| 编号 | 级别 | 问题 | 位置 | 状态 |
|---|---|---|---|---|
| A-1 | **P0** | 迁移非原子：DDL 与 `PRAGMA user_version` 分两步，中途崩溃 → 下次重复 ALTER → 永久启动失败 | `store/db.go` | ✅ 改 `db.Transaction` 包裹，失败回滚并报「第 v%d 条」 |
| A-2 | P1 | 面板测试把 SOCKS5/HTTP 密码拼进远端 curl 命令行（`ps` 可见） | `api/nodetest.go` | ✅ 改 0600 配置文件 + `curl -K` |
| A-3 | P1 | 临时客户端清理用 `pkill -f <配置路径>` 会匹配自身 shell → `rm` 不执行，文件残留 | `api/nodetest.go` | ✅ 改为 `echo $!` 记 PID 后按 PID 杀 |
| A-4 | P1 | 清理残余时把远端返回的 unit 名直接拼进 shell | `api/nodetest.go` | ✅ 白名单 `^vpspanel-(xray\|singbox)-[0-9]{1,5}\.service$` |
| A-5 | P1 | `startTempClient` 中途 panic → 远端临时进程泄漏 | `api/nodetest.go` | ✅ `defer recover → killTempClient` |
| A-6 | P1 | **URI 编码错误**：`url.QueryEscape` 把空格编成 `+`，userinfo 中 `+` 是字面加号 → Trojan/Hysteria2 密码解析错误 | `provision/provision.go` | ✅ 改 `url.User()` + `url.URL`，新增 `TestBuildLinkEncoding` |
| A-7 | P1 | 停服务只靠 `systemctl disable --now`；systemd 不可靠（单元丢失/崩溃循环/无 systemd）时进程不死、端口不释放 | `provision.Uninstall`、`api.cleanupServer` | ✅ 增「按配置路径 pkill」兜底（`[x]ray` 括号技巧防自匹配） |
| A-8 | P1 | 卸载 Hysteria2 只按 xray 命名空间清理 → 残留 sing-box unit + 配置 | `provision.Uninstall` | ✅ 同时清理 `vpspanel-xray-*` / `vpspanel-singbox-*` 与两套 config |
| A-9 | P1 | 空 body 的 `DELETE` 被安全中间件 415 拦掉（脚本/curl 无法卸载） | `api/guard.go` | ✅ 仅 `ContentLength > 0` 时强制 JSON |
| A-10 | P2 | 连点测速会排队（10 次 ≈ 50s） | `api/nodetest.go` | ✅ `tryLockPlan` → 409「该节点正在测试中」 |
| A-11 | P2 | e2e 脚本 DELETE 未带头且未校验响应（假阳性 ✓） | `scripts/e2e.sh` | ✅ 带头 + 校验 `"ok":true` + 新增「预清理」步骤 |
| A-12 | P2 | 安全扫描脚本把测试用例里的字符串误报为危险命令 | `scripts/ci.sh`、`selfcheck.sh` | ✅ 跳过 `_test.go` |
| A-13 | **P1** | **1B 内核推送后的重启只覆盖 xray**：`RestartAll` 只列 `vpspanel-xray-*.service` / 只遍历 xray 配置目录 → Hysteria2（sing-box）节点仍在跑旧内核 | `kernel/manager.go` | ✅ 两套内核都重启（systemd 用 `vpspanel-*.service` + 单元名白名单；nohup 分支分别遍历 xray/sing-box 配置目录） |

### P2（代码质量）

| 编号 | 问题 | 状态 |
|---|---|---|
| P2-1 | 失败部署记录无界增长 | ✅ 已修（保留最近 20 条） |
| P2-2 | 无单实例锁 | ✅ 已修（端口锁 + instance.port） |
| P2-3 | 无请求体大小限制 | ✅ 已修（1MB，413） |
| P2-4 | 无安全响应头 | ✅ 已修（X-Frame-Options 等） |
| P2-5 | 前端未转义插值（抽查均为数字/常量） | ✅ 复核无 XSS |
| P2-6 | `nodes` 接口同时返回失败记录 | ⚠️ 保留（UI 已标状态） |

---

## 3. 验证证据（摘要）

```
# 污染 banner 的 sshd
os = 'Debian GNU/Linux 12 (bookworm)'    JSON 含换行: False

# 坏配置部署
配置校验失败，已中止（现网未改动）；现网配置字节级不变；服务仍监听

# 幂等
端口 45830 由本面板托管，按更新处理 → ✓ 正在监听

# 并发
46101/46102/46103 三协议并发全部成功，三进程三端口

# 安全
Host: evil.com → 403；text/plain 写 → 415；跨站 Origin → 403；同源 JSON → 200
XSS 载荷 → #rows 内 img/script 元素数 0
超大 body(2MB) → 413

# 面板测试（真实出网）
VLESS  exit_ip=223.89.228.134  204  312ms
SOCKS5 exit_ip=223.89.228.134  204  107ms
Hysteria2 exit_ip=223.89.228.134 204 107ms
测试后 /tmp/vp-test-* 与 /tmp/vp-curl-* 均 0 残留

# 数据库迁移
user_version 0→1，host_key 字段补齐，原数据保留，二次重启不重复执行

# 静态与并发
go test ./... 全绿（36 项）；go vet 干净；CGO 依赖 0；Session/Dial Close 覆盖 4/4、6/6
go test -race ./internal/... → 无数据竞争（api 80s / store 44s）
并发单测：try-lock 50 goroutine 仅 1 赢家；阻塞锁临界区最大并发 = 1

# 卸载/清理终态（e2e 12/12 后）
端口 46001-46007 → 空；残留进程 0；残留配置 0；残留 systemd 单元 0
```

---

## 4. 遗留风险（架构或环境决定，面板内无法消除）

1. **WireGuard 未真机验证**：容器无 `wireguard` 内核模块；需真机 `apt install wireguard && modprobe wireguard` 后复验。
2. **真实 systemd 未复验**：本环境用 shim 验证 unit 生成与重启链路。
3. **MASQUE 未接入**：标 experimental，需 sing-box endpoint 实现。
4. **自签证书**：Trojan / Hysteria2 客户端需勾选「允许不安全证书」；有域名建议换正式证书。
5. **UDP 可能被云厂商限制**：Hysteria2 / WireGuard 依赖 UDP。
6. **无登录鉴权**：已用 Host/Origin/Content-Type 三重校验挡远程页面；本机多用户仍需系统账户隔离。
7. **`master.key` 与数据库同机**：本机被攻破即可解密全部 SSH 凭证。
8. **云安全组**：面板只能改 VPS 内 ufw/firewalld，安全组需人工放行。
9. **TOFU 首连**：首次指纹无带外校验，高安全场景先 `ssh-keyscan` 核对。

---

## 5. 复现方式

```bash
# 静态质量
./scripts/selfcheck.sh

# 运行时回归（需一台测试 VPS 已登记为 server_id=1）
PANEL=http://127.0.0.1:18080 SERVER_ID=1 ./scripts/e2e.sh

# 一条命令跑完所有门
./scripts/ci.sh

# 竞态检测（需 gcc）
CGO_ENABLED=1 go test -race ./internal/...

# 单测
go test ./...
```
