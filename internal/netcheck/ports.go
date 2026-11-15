// Package netcheck 在 Go 侧解析远端「监听中的端口」，而不是靠 shell 里 grep 的输出。
//
// 为什么不用 `ss ... | grep -c`：
//   - SSH 会话可能把登录告警（如 "Could not chdir to home directory ..."）写进 stderr，
//     若执行器合并了 stdout/stderr，grep 的计数就会被污染，导致「端口被占用」误报；
//   - grep 命中 `:443` 也会误命中 `:4439`，不够严格。
//
// 因此这里：只读 stdout → 拿到监听表 → 在 Go 里按「地址:端口」精确解析 → 精确比较端口号。
package netcheck

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"vpspanel/internal/sshx"
)

// localAddrRe 只接受「本端地址:端口」形式的 token，例如：
//
//	0.0.0.0:443   *:443   [::]:443   127.0.0.1:8080   fe80::1%eth0:22
//
// 远端地址（如 1.2.3.4:443 与 0.0.0.0:*）不会被误判成监听端口。
var localAddrRe = regexp.MustCompile(`^(?:\[[0-9a-fA-F:.]+\]|\*|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:.%a-zA-Z]+):(\d+)$`)

// ParseListening 从 ss / netstat / lsof 的原始输出中解析出「端口 → 本端地址」。
// 该函数是纯函数，便于单元测试（传入被 stderr 污染过的文本也不会误判）。
func ParseListening(raw string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 只处理监听行：ss -l 本身只有监听，netstat/lsof 再兜一层状态判断
		lower := strings.ToLower(line)
		if strings.Contains(lower, "established") || strings.Contains(lower, "time_wait") ||
			strings.Contains(lower, "close_wait") || strings.Contains(lower, "syn_sent") {
			continue
		}
		if strings.Contains(lower, "listen") {
			// ss/netstat：取第一个形如 addr:port 的 token
			for _, f := range strings.Fields(line) {
				if m := localAddrRe.FindStringSubmatch(f); len(m) == 2 {
					if p, err := strconv.Atoi(m[1]); err == nil {
						if _, ok := out[p]; !ok {
							out[p] = addrPart(f)
						}
					}
					break
				}
			}
			continue
		}
		// lsof 格式：xray 123 root 4u IPv6 ... TCP *:443 (LISTEN)
		for _, f := range strings.Fields(line) {
			if m := localAddrRe.FindStringSubmatch(f); len(m) == 2 {
				if p, err := strconv.Atoi(m[1]); err == nil {
					if _, ok := out[p]; !ok {
						out[p] = addrPart(f)
					}
				}
				break
			}
		}
	}
	return out
}

func addrPart(token string) string {
	if i := strings.LastIndex(token, ":"); i > 0 {
		return token[:i]
	}
	return token
}

// ListeningPorts 读取远端监听端口表（TCP + UDP），按 ss → netstat → lsof 合并。
func ListeningPorts(ctx context.Context, client *ssh.Client) (map[int]string, string, error) {
	probes := []struct{ name, cmd string }{
		{"ss", "ss -H -ltnu 2>/dev/null"},
		{"netstat", "netstat -ltnu 2>/dev/null"},
		{"lsof", "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null"},
		{"lsof", "lsof -nP -iUDP 2>/dev/null"},
	}
	out := map[int]string{}
	tool := ""
	var lastErr error
	for _, p := range probes {
		raw, err := sshx.RunOut(ctx, client, p.cmd)
		if err != nil {
			lastErr = err
			continue
		}
		m := ParseListening(raw)
		if len(m) > 0 && tool == "" {
			tool = p.name
		}
		for k, v := range m {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, "", fmt.Errorf("读取监听端口失败: %w", lastErr)
	}
	return out, tool, nil
}

// InUse 判断端口是否真的处于 LISTEN 状态，返回 (占用, 说明)。
// 说明里只会包含「地址与工具名」，不含任何远端 stderr 文本。
func InUse(ctx context.Context, client *ssh.Client, port int) (bool, string, error) {
	m, tool, err := ListeningPorts(ctx, client)
	if err != nil {
		return false, "", err
	}
	if addr, ok := m[port]; ok {
		return true, fmt.Sprintf("%s 显示 %s:%d 正在监听", tool, addr, port), nil
	}
	return false, "", nil
}
