// Package sshx 封装到远端 VPS 的 SSH 连接与基础信息采集。
// 设计约束：
//   - 只做「固定白名单命令」，不接受拼接的用户输入；
//   - 所有命令带超时，避免单台机器卡死拖垮整个巡检；
//   - HostKey 校验在 M1 做指纹固定，M0 先放行以便快速打通链路。
package sshx

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Credentials struct {
	User       string
	Port       int
	Password   string
	PrivateKey []byte
	Passphrase string
	Timeout    time.Duration
}

type Info struct {
	OS       string            `json:"os"`        // 干净单行：Debian GNU/Linux 12 (bookworm)
	Kernel   string            `json:"kernel"`    // Linux 5.15.0-91-generic
	Arch     string            `json:"arch"`      // x86_64
	Cores    int               `json:"cores"`     // 4
	MemMB    int               `json:"mem_mb"`    // 11884
	MemTotal string            `json:"mem_total"` // 11884 MB
	DiskGB   int               `json:"disk_gb"`   // 105
	DiskRoot string            `json:"disk_root"` // 105 GB
	Specs    string            `json:"specs"`     // 4 核 / 11884 MB / 105 GB
	Raw      map[string]string `json:"-"`         // 调试用原始输出（不对外）
}

func (c Credentials) authMethods() ([]ssh.AuthMethod, error) {
	if len(c.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if c.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(c.PrivateKey, []byte(c.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(c.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	if c.Password != "" {
		return []ssh.AuthMethod{ssh.Password(c.Password)}, nil
	}
	return nil, fmt.Errorf("未提供密码或私钥")
}

// Dial 建立连接。ctx 用于整体超时控制。
// 可选的 HostKeys 用于固定主机指纹（TOFU）；不传则退化为不校验（仅调试用）。
func Dial(ctx context.Context, host string, c Credentials, hk ...*HostKeys) (*ssh.Client, error) {
	auths, err := c.authMethods()
	if err != nil {
		return nil, err
	}
	port := c.Port
	if port == 0 {
		port = 22
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// 默认不校验（仅限调试）；生产路径必须传入指纹库
	var hostKeyCb ssh.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	if len(hk) > 0 && hk[0] != nil {
		hostKeyCb = hk[0].Callback(addr)
	}

	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            auths,
		HostKeyCallback: hostKeyCb,
		Timeout:         timeout,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP 连接失败: %w", err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH 握手失败: %w", err)
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// Run 执行单条命令，返回 stdout（去掉首尾空白）。
func Run(ctx context.Context, client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(cmd)
		ch <- result{out, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		return strings.TrimSpace(string(r.out)), r.err
	}
}

// RunOut 只执行命令并返回 stdout（丢弃 stderr）。
// 采集类命令一律走这里：MOTD / chdir 告警都写在 stderr，不能混进数据字段。
func RunOut(ctx context.Context, client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := sess.Output(cmd)
		ch <- result{out, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		// 只清洗、不 TrimSpace 成多行，交给 clean.go 统一处理
		return string(r.out), r.err
	}
}

// Probe 采集系统基础信息，用于「添加 VPS 后自动填充」。
func Probe(ctx context.Context, client *ssh.Client) (Info, error) {
	var info Info
	info.Raw = map[string]string{}

	// uname：只取 stdout，再压成单行
	if s, err := RunOut(ctx, client, "uname -srm 2>/dev/null"); err == nil {
		info.Raw["uname"] = Sanitize(s)
		parts := strings.Fields(Sanitize(s))
		if len(parts) >= 3 {
			info.Kernel = Truncate(parts[0]+" "+parts[1], 40)
			info.Arch = Truncate(parts[2], 20)
		} else if len(parts) > 0 {
			info.Kernel = Truncate(parts[0], 40)
		}
	}

	// OS：优先 os-release 的 PRETTY_NAME，被 MOTD 污染时由 OSName 挑出干净的一行
	if s, err := RunOut(ctx, client, `sh -c '. /etc/os-release 2>/dev/null; printf "%s" "${PRETTY_NAME:-}"'`); err == nil {
		info.Raw["os_release"] = Sanitize(s)
		info.OS = OSName(s)
	}
	if info.OS == "" {
		if s, err := RunOut(ctx, client, `sh -c 'lsb_release -ds 2>/dev/null || head -1 /etc/issue 2>/dev/null'`); err == nil {
			info.OS = OSName(s)
		}
	}

	if s, err := RunOut(ctx, client, "nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo"); err == nil {
		if n, e := strconv.Atoi(OneLine(s)); e == nil && n > 0 {
			info.Cores = n
		}
	}
	if s, err := RunOut(ctx, client, `awk '/MemTotal/{printf "%.0f", $2/1024}' /proc/meminfo`); err == nil {
		if n, e := strconv.Atoi(OneLine(s)); e == nil && n > 0 {
			info.MemMB = n
			info.MemTotal = itoa(n) + " MB"
		}
	}
	if s, err := RunOut(ctx, client, `df -BG --output=size / 2>/dev/null | tail -1 | tr -d "G "`); err == nil {
		if n, e := strconv.Atoi(OneLine(s)); e == nil && n > 0 {
			info.DiskGB = n
			info.DiskRoot = itoa(n) + " GB"
		}
	}

	// 最终保险：对外字段一律单行、无控制字符
	info.OS = Sanitize(info.OS)
	info.Kernel = Sanitize(info.Kernel)
	info.Arch = Sanitize(info.Arch)
	info.MemTotal = Sanitize(info.MemTotal)
	info.DiskRoot = Sanitize(info.DiskRoot)
	info.Specs = Specs(info.Cores, info.MemMB, info.DiskGB)

	if info.OS == "" && info.Kernel == "" {
		return info, fmt.Errorf("未取到有效系统信息（可能被 MOTD 或权限问题干扰）")
	}
	return info, nil
}
