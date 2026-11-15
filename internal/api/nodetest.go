package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"

	"vpspanel/internal/netcheck"
	"vpspanel/internal/provision"
	"vpspanel/internal/sshx"
	"vpspanel/internal/store"
)

// deployPayload 是 deployments.config_json 的结构。
type deployPayload struct {
	Link string            `json:"link"`
	Meta map[string]string `json:"meta"`
	Spec *provision.Spec   `json:"spec"`
}

// unitNameRe 只允许本面板的单元命名（vpspanel-xray-<port>.service 等）。
var unitNameRe = regexp.MustCompile(`^vpspanel-(xray|singbox)-[0-9]{1,5}\.service$`)

var ipRe2 = regexp.MustCompile(`^\s*((?:\d{1,3}\.){3}\d{1,3})\s*$`)

// nodeTest 用「临时客户端进程 + 本地 SOCKS 拨号」做真实连通性测试，返回出口 IP 与延迟。
func (s *Server) nodeTest(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var d store.Deployment
	if err := s.DB.First(&d, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "error": "节点不存在"})
		return
	}
	var pl deployPayload
	if err := json.Unmarshal([]byte(d.ConfigJSON), &pl); err != nil || pl.Spec == nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": "该节点缺少可测试的参数，请重新部署一次"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
	defer cancel()

	client, srv, err := s.dialServer(ctx, d.ServerID, 10*time.Second)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	defer client.Close()

	// 同一节点已在测试中 → 直接拒绝，避免连点 10 次排出 10 个远端进程
	unlock, ok := s.tryLockPlan(d.ServerID, d.Port)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"ok": false, "error": "该节点正在测试中，请稍候再试"})
		return
	}
	defer unlock()

	proto := pl.Spec.Protocol
	if proto == "wireguard" {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": "WireGuard 暂不支持面板内测试（需本地 wg 客户端）"})
		return
	}

	var socksAddr string
	var cleanup func()
	started := time.Now()
	_ = started

	if provision.NeedsLocalClient(proto) {
		localPort, cfgPath, pid, startErr := startTempClient(ctx, client, d.ID, srv.Host, pl.Spec)
		if startErr != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": startErr.Error()})
			return
		}
		socksAddr = fmt.Sprintf("127.0.0.1:%d", localPort)
		cleanup = func() { killTempClient(context.Background(), client, d.ID, cfgPath, pid) }
	} else {
		// SOCKS5 / HTTP：直接用 curl 的代理参数，无需临时进程
		socksAddr = fmt.Sprintf("%s:%d", srv.Host, d.Port)
		if pl.Spec.User != "" {
			socksAddr = fmt.Sprintf("%s:%s@%s:%d", pl.Spec.User, pl.Spec.Password, srv.Host, d.Port)
		}
		cleanup = func() {}
	}
	defer cleanup()

	// 首次包含握手/建链开销，跑两次取较小值更能反映真实延迟
	// 凭据只落在 0600 的 curl 配置文件里，不出现在命令行（避免 ps 可见）
	args, confCleanup, cerr := curlProxyArgs(ctx, client, proto, socksAddr, d.ID)
	if cerr != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": cerr.Error()})
		return
	}
	defer confCleanup()

	latency, code, err := probeThrough(ctx, client, args)
	if err == nil {
		if l2, _, e2 := probeThrough(ctx, client, args); e2 == nil && l2 > 0 && l2 < latency {
			latency = l2
		}
	}
	if err != nil {
		s.audit("node.test", srv.Host, fmt.Sprintf("port=%d fail", d.Port))
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error(), "latency_ms": latency})
		return
	}

	// 取出口 IP（失败不影响结论，只标注未取到）
	exitIP := ""
	if out, err := sshx.RunOut(ctx, client, fmt.Sprintf(
		"curl -s --max-time 8 %s https://api.ip.sb/ip 2>/dev/null || true", args)); err == nil {
		if m := ipRe2.FindStringSubmatch(out); m != nil {
			exitIP = m[1]
		}
	}

	s.audit("node.test", srv.Host, fmt.Sprintf("port=%d ok %dms", d.Port, latency))
	c.JSON(http.StatusOK, gin.H{
		"ok": true, "latency_ms": latency, "http_code": code, "exit_ip": exitIP,
	})
}

// startTempClient 在远端拉起临时客户端进程，返回本地 SOCKS 端口与配置路径。
func startTempClient(ctx context.Context, client *ssh.Client, deployID uint, host string, spec *provision.Spec) (int, string, int, error) {
	// 选一个远端空闲端口
	localPort := 20000 + int(deployID)%20000
	for i := 0; i < 20; i++ {
		if busy, _, _ := netcheck.InUse(ctx, client, localPort); !busy {
			break
		}
		localPort++
	}

	cfgJSON, err := provision.RenderClientConfig(host, spec, localPort)
	if err != nil {
		return 0, "", 0, err
	}
	cfgPath := fmt.Sprintf("/tmp/vp-test-%d.json", deployID)
	logPath := fmt.Sprintf("/tmp/vp-test-%d.log", deployID)

	// 写配置（用 shell heredoc 传输，避免额外依赖）
	if err := writeRemoteFile(ctx, client, cfgPath, cfgJSON); err != nil {
		return 0, "", 0, fmt.Errorf("写入测试配置失败: %w", err)
	}

	var startCmd string
	if provision.ClientCore(spec.Protocol) == "sing-box" {
		startCmd = fmt.Sprintf("nohup /usr/local/bin/sing-box run -c %s >%s 2>&1 & echo $!", cfgPath, logPath)
	} else {
		startCmd = fmt.Sprintf("nohup /usr/local/bin/xray -config %s >%s 2>&1 & echo $!", cfgPath, logPath)
	}
	// 一旦拉起进程，无论后续 return/panic 都必须清理
	defer func() {
		if r := recover(); r != nil {
			killTempClient(context.Background(), client, deployID, cfgPath, 0)
			panic(r)
		}
	}()

	pidOut, err2 := sshx.RunOut(ctx, client, startCmd)
	if err2 != nil {
		killTempClient(ctx, client, deployID, cfgPath, 0)
		return 0, "", 0, fmt.Errorf("启动临时客户端失败: %w", err2)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(pidOut))

	// 等本地 SOCKS 起来
	for i := 0; i < 15; i++ {
		time.Sleep(400 * time.Millisecond)
		if busy, _, _ := netcheck.InUse(ctx, client, localPort); busy {
			return localPort, cfgPath, pid, nil
		}
	}
	logs, _ := sshx.RunOut(ctx, client, "tail -5 "+logPath+" 2>/dev/null")
	killTempClient(ctx, client, deployID, cfgPath, pid)
	return 0, "", 0, fmt.Errorf("临时客户端未监听 %d：%s", localPort, sshx.Sanitize(logs))
}

// killTempClient 按 PID 精确结束临时进程，并删除临时配置/日志（不造成资源泄漏）。
func killTempClient(ctx context.Context, client *ssh.Client, deployID uint, cfgPath string, pid int) {
	kill := ""
	if pid > 0 {
		kill = fmt.Sprintf("kill %d 2>/dev/null; sleep 0.3; kill -9 %d 2>/dev/null;", pid, pid)
	}
	_, _ = sshx.RunOut(ctx, client, fmt.Sprintf("%s rm -f %s /tmp/vp-test-%d.log; true",
		kill, cfgPath, deployID))
}

// curlProxyConf 生成 curl 配置文件内容（凭据只出现在文件里，不进命令行）。
func curlProxyConf(proto, proxyAddr string) string {
	switch proto {
	case "http":
		return fmt.Sprintf("proxy = \"http://%s\"\n", proxyAddr)
	case "socks":
		return fmt.Sprintf("proxy = \"socks5h://%s\"\n", proxyAddr)
	}
	return ""
}

// curlProxyArgs 准备代理参数：socks/http 用 0600 配置文件；其它协议用本地无凭据 SOCKS。
func curlProxyArgs(ctx context.Context, client *ssh.Client, proto, proxyAddr string, deployID uint) (string, func(), error) {
	conf := curlProxyConf(proto, proxyAddr)
	if conf == "" {
		return "--socks5-hostname " + proxyAddr, func() {}, nil
	}
	path := fmt.Sprintf("/tmp/vp-curl-%d.conf", deployID)
	if err := writeRemoteFile(ctx, client, path, conf); err != nil {
		return "", func() {}, fmt.Errorf("写入 curl 配置失败: %w", err)
	}
	cleanup := func() {
		_, _ = sshx.RunOut(context.Background(), client, "rm -f "+path+"; true")
	}
	return "-K " + path, cleanup, nil
}

// probeThrough 通过代理访问 generate_204，返回延迟(ms) 与 HTTP 状态码。
func probeThrough(ctx context.Context, client *ssh.Client, proxyArgs string) (int64, string, error) {
	url := "http://www.gstatic.com/generate_204"
	cmd := fmt.Sprintf(`curl -s -o /dev/null --max-time 10 %s -w '%%{http_code} %%{time_total}' %s 2>/dev/null || true`, proxyArgs, url)
	out, err := sshx.RunOut(ctx, client, cmd)
	if err != nil {
		return 0, "", fmt.Errorf("测试请求失败: %w", err)
	}
	fields := strings.Fields(sshx.Sanitize(out))
	if len(fields) < 2 {
		return 0, "", fmt.Errorf("代理不通（curl 无输出，可能端口/凭证错误或被防火墙拦截）")
	}
	code := fields[0]
	sec, perr := strconv.ParseFloat(fields[1], 64)
	if perr != nil {
		return 0, "", fmt.Errorf("解析延迟失败: %s", fields[1])
	}
	if code != "204" && code != "200" {
		return int64(sec * 1000), code, fmt.Errorf("代理返回异常状态码 %s（请求未真正出网）", code)
	}
	return int64(sec * 1000), code, nil
}

// writeRemoteFile 通过 cat 写入远端文件（内容不经过 shell 解析）。
func writeRemoteFile(ctx context.Context, client *ssh.Client, path, content string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		_, _ = stdin.Write([]byte(content))
		_ = stdin.Close()
	}()
	return sess.Run("cat > " + path + " && chmod 600 " + path)
}

// cleanupServer 清理该服务器上由本面板创建的所有节点服务与配置（不碰系统其它组件）。
func (s *Server) cleanupServer(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Minute)
	defer cancel()

	unlock := s.lockPlan(uint(id), 0)
	defer unlock()

	client, srv, err := s.dialServer(ctx, uint(id), 10*time.Second)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	defer client.Close()

	var logs []string
	add := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }

	// 1) systemd 单元（本面板命名：vpspanel-xray-*, vpspanel-singbox-*）
	if _, err := sshx.RunOut(ctx, client, "test -d /run/systemd/system && echo yes"); err == nil {
		out, _ := sshx.RunOut(ctx, client,
			`systemctl list-units --type=service --all --no-legend 'vpspanel-*' 2>/dev/null | awk '{print $1}'`)
		for _, u := range strings.Fields(out) {
			// 单元名来自远端输出，进入 shell 前必须白名单校验（防被篡改的 unit 名注入）
			if !unitNameRe.MatchString(u) {
				add("跳过可疑单元名：%s", sshx.Sanitize(u))
				continue
			}
			_, _ = sshx.RunOut(ctx, client, "systemctl disable --now "+u+" 2>/dev/null || true")
			_, _ = sshx.RunOut(ctx, client, "rm -f /etc/systemd/system/"+u)
			add("已停止并移除单元 %s", u)
		}
		_, _ = sshx.RunOut(ctx, client, "systemctl daemon-reload 2>/dev/null || true")
	} else {
		add("未检测到 systemd，按配置路径结束进程")
	}

	// 兜底：无论 systemd 是否可用（单元文件已丢、服务崩溃循环、shim 环境等），
	// 都按「配置路径前缀」再杀一次，确保端口真正释放。
	// 用 [x]ray 的括号技巧避免 pkill 匹配到自己这条命令。
	killOut, _ := sshx.RunOut(ctx, client,
		`pkill -f "[x]ray -config /usr/local/etc/xray/config-" 2>/dev/null; `+
			`pkill -f "[s]ing-box run -c /usr/local/etc/sing-box/config-" 2>/dev/null; `+
			`sleep 0.3; true`)
	_ = killOut
	add("已按配置路径兜底结束残留进程")

	// 2) 配置文件与备份（仅本面板命名空间）
	out, _ := sshx.RunOut(ctx, client,
		`rm -f /usr/local/etc/xray/config-*.json /usr/local/etc/xray/config-*.json.bak.* /usr/local/etc/xray/config-*.new.json; `+
			`rm -f /usr/local/etc/sing-box/config-*.json /usr/local/etc/sing-box/config-*.json.bak.*; `+
			`ls -1 /usr/local/etc/xray/config-*.json 2>/dev/null | wc -l`)
	add("已清理配置（剩余 %s 个）", strings.TrimSpace(out))

	// 3) WireGuard 接口
	_, _ = sshx.RunOut(ctx, client,
		`for c in /etc/wireguard/wgvp*.conf; do [ -f "$c" ] || continue; i=$(basename "$c" .conf); wg-quick down "$i" 2>/dev/null || true; rm -f "$c"; done; true`)
	add("已清理 WireGuard 接口与配置")

	// 4) 测试残留
	_, _ = sshx.RunOut(ctx, client, `pkill -f "[v]p-test-" 2>/dev/null || true; sleep 0.2; rm -f /tmp/vp-test-*.json /tmp/vp-test-*.log; true`)

	// 5) DB 记录
	res := s.DB.Where("server_id = ?", id).Delete(&store.Deployment{})
	add("已删除面板侧节点记录 %d 条", res.RowsAffected)

	s.audit("server.cleanup", srv.Host, fmt.Sprintf("removed %d records", res.RowsAffected))
	c.JSON(http.StatusOK, gin.H{"ok": true, "logs": logs, "records": res.RowsAffected})
}
