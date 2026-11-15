// Package socks5probe 用于测试家宽 SOCKS5 节点：TCP 连通 → 握手 → 认证 → CONNECT → 出口 IP。
package socks5probe

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type Result struct {
	Reachable  bool   `json:"reachable"`  // TCP 能否连上
	Handshake  bool   `json:"handshake"`  // SOCKS5 版本协商成功
	AuthOK     bool   `json:"auth_ok"`    // 认证通过（无认证时也为 true）
	NeedAuth   bool   `json:"need_auth"`  // 服务端要求用户名密码
	ConnectOK  bool   `json:"connect_ok"` // CONNECT 目标成功
	ExitIP     string `json:"exit_ip"`    // 通过该节点访问外网看到的出口 IP
	LatencyMS  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
	Stage      string `json:"stage"` // 失败所在阶段，便于定位
	ServerHint string `json:"server_hint"`
}

const (
	stageTCP       = "tcp"
	stageGreeting  = "greeting"
	stageAuth      = "auth"
	stageConnect   = "connect"
	stageExitIP    = "exit_ip"
	unknownExitURL = "api.ipify.org:80"
)

// Probe 完整测试一个 SOCKS5 节点，永不 panic，失败通过 Result.Error 返回。
func Probe(ctx context.Context, addr string, port int, user, pass string) *Result {
	res := &Result{ServerHint: fmt.Sprintf("%s:%d", addr, port)}
	start := time.Now()

	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, fmt.Sprint(port)))
	if err != nil {
		res.Stage = stageTCP
		res.Error = "TCP 连接失败: " + err.Error()
		return res
	}
	defer conn.Close()
	res.Reachable = true
	res.LatencyMS = time.Since(start).Milliseconds()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)

	// ── 1. 版本协商 ──
	methods := []byte{0x00} // 无认证
	if user != "" {
		methods = append(methods, 0x02) // 用户名密码
	}
	req := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		res.Stage = stageGreeting
		res.Error = "发送握手失败: " + err.Error()
		return res
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		res.Stage = stageGreeting
		res.Error = "读取握手响应失败（可能不是 SOCKS5 服务）: " + err.Error()
		return res
	}
	if head[0] != 0x05 {
		res.Stage = stageGreeting
		res.Error = fmt.Sprintf("不是 SOCKS5 协议（收到版本 0x%02x）", head[0])
		return res
	}
	if head[1] == 0xFF {
		res.Stage = stageGreeting
		res.Error = "服务端拒绝所有认证方式（可能需要用户名密码，或不允许当前 IP）"
		return res
	}
	res.Handshake = true

	// ── 2. 认证 ──
	if head[1] == 0x02 {
		res.NeedAuth = true
		if user == "" {
			res.Stage = stageAuth
			res.Error = "服务端要求用户名密码，但未提供"
			return res
		}
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, []byte(user)...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, []byte(pass)...)
		if _, err := conn.Write(authReq); err != nil {
			res.Stage = stageAuth
			res.Error = "发送认证失败: " + err.Error()
			return res
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(br, ar); err != nil {
			res.Stage = stageAuth
			res.Error = "读取认证响应失败: " + err.Error()
			return res
		}
		if ar[1] != 0x00 {
			res.Stage = stageAuth
			res.Error = "用户名或密码错误（认证被拒绝）"
			return res
		}
	}
	res.AuthOK = true

	// ── 3. CONNECT 到目标，验证能否真正转发 ──
	target := exitEndpoint()
	if err := doConnect(conn, br, target); err != nil {
		res.Stage = stageConnect
		res.Error = "CONNECT 失败: " + err.Error()
		return res
	}
	res.ConnectOK = true
	res.LatencyMS = time.Since(start).Milliseconds()

	// ── 4. 读取出口 IP ──
	ip, err := readExitIP(conn, target)
	if err != nil {
		res.Stage = stageExitIP
		res.Error = "隧道已建立，但出口 IP 探测失败（不影响可用性）: " + err.Error()
		return res
	}
	res.ExitIP = ip
	res.LatencyMS = time.Since(start).Milliseconds()
	return res
}

func doConnect(conn net.Conn, br *bufio.Reader, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		if len(host) > 255 {
			return fmt.Errorf("目标域名过长")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	req = append(req, p...)

	if _, err := conn.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(br, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("响应版本异常 0x%02x", reply[0])
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("REP=0x%02x（%s）", reply[1], repText(reply[1]))
	}
	// 跳过 BND.ADDR + BND.PORT
	switch reply[3] {
	case 0x01:
		if _, err := io.ReadFull(br, make([]byte, 4+2)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(br, make([]byte, 16+2)); err != nil {
			return err
		}
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return err
		}
		if _, err := io.ReadFull(br, make([]byte, int(l[0])+2)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("未知 ATYP 0x%02x", reply[3])
	}
	return nil
}

func repText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	}
	return "unknown"
}

// exitEndpoint 允许自定义出口 IP 探测地址（默认 api.ipify.org:80）。
func exitEndpoint() string {
	if v := os.Getenv("VPSPANEL_EXIT_IP_ENDPOINT"); v != "" {
		return v
	}
	return unknownExitURL
}

var ipRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func readExitIP(conn net.Conn, target string) (string, error) {
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: vpspanel/1.0\r\nConnection: close\r\n\r\n", strings.Split(target, ":")[0])
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	body, err := io.ReadAll(io.LimitReader(conn, 64*1024))
	if err != nil && len(body) == 0 {
		return "", err
	}
	if ip := ipRe.FindString(string(body)); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("响应中未找到 IP")
}
