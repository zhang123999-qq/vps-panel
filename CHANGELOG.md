# Changelog

本项目按「版本 = 迭代轮次」推进，记录每个版本的可验证变化。

## v1.1.1

**部署权限与错误透传（线上事故修复）**

- 新增 `internal/sshx/privilege.go`：`DetectPrivilege` / `Wrap(sudo -n)` / `Check` / `Classify`
- 内核安装重写为 `installKernel` 六步：权限预检 → 上传 `/tmp/<name>_upload.gz` → `gunzip + chmod + version`（stdout/stderr 全量回显）→ 备份 → `cp` 到同目录临时名再 `mv`（规避 `Text file busy`）→ 复核版本
- 修复「安装失败，已回滚到原本版」无原因：失败时按 `Classify` 输出 `Permission denied` / `command not found` / `Exec format error` / `sudo 缺免密`
- 回滚过程打印「正在执行回滚…」「旧内核已恢复」
- 部署引擎 `installService` / `Uninstall` / WireGuard 全部支持非 root + 免密 sudo

## v1.0.2

- 修复 1B 内核推送后只重启 xray、Hysteria2（sing-box）仍跑旧内核（`RestartAll` 覆盖两套命名空间 + 单元名白名单）

## v1.0.1

- `-race` 竞态检测全包通过，新增并发单测（try-lock 单赢家、临界区不重叠）
- 卸载链路：`systemctl` 不可靠时按配置路径 `pkill` 兜底；覆盖 xray / sing-box 双命名空间
- 空 body 的 `DELETE` 不再被 415 拦截

## v1.0.0

- 修复 P0：数据库迁移非原子（DDL 与 `user_version` 同事务提交，失败回滚）
- 修复 P1：URI 编码（`url.User` 替代 `QueryEscape`，空格 → `%20`）、清理时单元名白名单、测速 panic 兜底、空 body DELETE

## v0.9.x

- `PRAGMA user_version` 顺序迁移机制（含降级保护与失败回滚）
- 单节点「复制链接」、服务器「清理残余」、节点「面板测试」（真实出口 IP + 延迟，远端临时客户端按 PID 清理）
- 测速凭据改走 0600 curl 配置文件，不进远端命令行；连点 10 次返回 409

## v0.8.0

- WireGuard 接入（`wg-quick`，客户端 INI 输出；依赖缺失给出安装命令）

## v0.7.0

- `scripts/e2e.sh`：7 协议端到端回归（12 项，可重复执行）
- 修复并发写入与卸载残留（服务/配置/单元/进程四项归零）

## v0.6.x

- Trojan（自签 TLS）、Hysteria2（sing-box / QUIC-UDP）接入；协议覆盖 8 种
- 安全加固：CSRF / DNS rebinding 拦截、SSH 主机指纹 TOFU、请求体 1MB 上限、安全响应头
- 数据库迁移机制、失败记录裁剪、单实例锁

## v0.5.x

- 内核双层升级：1A 构建期脚本（`update-kernels.sh`，含 `--rollback`）/ 1B 运行时推送
- `LandingNode` 统一抽象：落地可选 VPS 或家宽 SOCKS5，链路走同一套流程
- 清理 stderr 污染、端口归属误判、防火墙静默成功等 20+ 项问题

## v0.4.0

- 内核一键更新、端口默认 443、前置+落地链路、家宽 SOCKS5 落地

## v0.3.0

- 部署引擎上线：VLESS+Reality / VMess / Shadowsocks / SOCKS5 / HTTP，9 步实时日志 + 失败回滚

## v0.2.x

- 服务器增删改查、SSH 密码/私钥认证、凭证 AES-256-GCM 加密、表单内「测试连接」

## v0.1.0

- 项目骨架：Go + Gin + 纯 Go SQLite（`CGO_ENABLED=0`）、内嵌前端、单 exe、仅监听 127.0.0.1
