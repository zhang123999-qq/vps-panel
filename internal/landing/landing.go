// Package landing 是「落地节点」统一抽象（P2）。
//
// 落地不只有普通 VPS：
//   - KindServer    : 已登记的 VPS，走 xray/sing-box 协议入站
//   - KindHomeSocks5: 家宽 SOCKS5 节点，走 SOCKS5 出站
//
// 链路的部署与测试只允许在这里分支，**禁止**在外面复制两套流程。
package landing

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"vpspanel/internal/provision"
	"vpspanel/internal/socks5probe"
	"vpspanel/internal/sshx"
	"vpspanel/internal/validate"
)

type Kind string

const (
	KindServer     Kind = "server"
	KindHomeSocks5 Kind = "home_socks5"
)

// Node 描述的是一份「可以给前置当出口」的落地。
type Node struct {
	Kind Kind
	ID   uint
	Name string

	// KindServer
	Host     string
	Port     int    // 落地监听端口
	Protocol string // vless-reality | vmess-ws
	UUID     string
	PubKey   string
	ShortID  string
	SNI      string
	PrivKey  string
	Dest     string
	Path     string

	// KindHomeSocks5
	SocksHost    string
	SocksPort    int
	SocksUser    string
	SocksPass    string
	ExpectExitIP string
}

// Label 用于日志/界面展示（不含任何凭证）。
func (n Node) Label() string {
	if n.Kind == KindHomeSocks5 {
		return fmt.Sprintf("家宽 SOCKS5 %s:%d", n.SocksHost, n.SocksPort)
	}
	return fmt.Sprintf("VPS %s:%d", n.Host, n.Port)
}

// Outbound 按落地类型生成出站配置。新增落地类型只需在这里加分支。
func (n Node) Outbound(tag string) (map[string]any, error) {
	switch n.Kind {
	case KindHomeSocks5:
		return provision.Socks5Outbound(tag, n.SocksHost, n.SocksPort, n.SocksUser, n.SocksPass), nil
	case KindServer:
		switch n.Protocol {
		case "vmess-ws":
			return provision.VMessWSOutbound(tag, n.Host, n.Host, n.Port, n.UUID, n.Path), nil
		case "vless-reality", "":
			return provision.VLESSRealityOutbound(tag, n.Host, n.Port, n.UUID, n.PubKey, n.ShortID, n.SNI), nil
		default:
			return nil, fmt.Errorf("不支持的落地协议: %s", n.Protocol)
		}
	default:
		return nil, fmt.Errorf("未知落地类型: %s", n.Kind)
	}
}

// Inbound 仅 KindServer 使用：为落地生成入站配置。
func (n Node) Inbound() (map[string]any, error) {
	if n.Kind != KindServer {
		return nil, fmt.Errorf("落地类型 %s 不需要入站配置", n.Kind)
	}
	switch n.Protocol {
	case "vmess-ws":
		return provision.WSInbound(n.Port, "vmess", n.UUID, n.Path), nil
	case "vless-reality", "":
		return provision.RealityInbound(n.Port, n.UUID, n.PrivKey, n.ShortID, n.Dest, n.SNI), nil
	}
	return nil, fmt.Errorf("不支持的落地协议: %s", n.Protocol)
}

// Reachable 检查「前置能否连到落地」（统一由调用方传入前置 SSH 连接）。
func (n Node) Reachable(ctx context.Context, from *ssh.Client) error {
	switch n.Kind {
	case KindServer:
		return tcpCheckFrom(ctx, from, n.Host, n.Port)
	case KindHomeSocks5:
		// 家宽节点通常不允许从 VPS 主动探测端口，直接做一次 SOCKS5 探测即可
		pr := socks5probe.Probe(ctx, n.SocksHost, n.SocksPort, n.SocksUser, n.SocksPass)
		if pr == nil || !pr.Reachable {
			return fmt.Errorf("家宽节点不可达: %s", errOf(pr))
		}
		if !pr.Handshake {
			return fmt.Errorf("SOCKS5 握手失败: %s", pr.Error)
		}
		if pr.NeedAuth && !pr.AuthOK {
			return fmt.Errorf("SOCKS5 认证失败: %s", pr.Error)
		}
		return nil
	}
	return fmt.Errorf("未知落地类型: %s", n.Kind)
}

// ExitIP 取落地出口 IP 并与预期比对（预期为空则只报告）。
func (n Node) ExitIP(ctx context.Context, from *ssh.Client) (string, error) {
	var ip string
	var err error
	switch n.Kind {
	case KindHomeSocks5:
		pr := socks5probe.Probe(ctx, n.SocksHost, n.SocksPort, n.SocksUser, n.SocksPass)
		if pr == nil || !pr.ConnectOK {
			return "", fmt.Errorf("经家宽节点取出口 IP 失败: %s", errOf(pr))
		}
		ip = pr.ExitIP
	case KindServer:
		if from == nil {
			return "", fmt.Errorf("缺少落地连接，无法探测出口 IP")
		}
		// 在落地机器上取公网 IP（失败再退化到本机地址）
		if o, e := sshx.RunOut(ctx, from, "curl -s -m 6 https://api.ipify.org 2>/dev/null || curl -s -m 6 http://ifconfig.me 2>/dev/null"); e == nil {
			ip = strings.TrimSpace(o)
		}
		if ip == "" {
			return "", fmt.Errorf("落地机器上无法获取出口 IP（可能无外网访问）")
		}
	}
	if ip == "" {
		// 未设置预期且探测不到（如受限网络）时不算失败，交由调用方决定是否提示
		if n.ExpectExitIP == "" {
			return "", nil
		}
		return "", fmt.Errorf("未取到出口 IP，无法校验预期值 %s", n.ExpectExitIP)
	}
	if n.ExpectExitIP != "" && !strings.Contains(ip, n.ExpectExitIP) {
		return ip, fmt.Errorf("出口 IP 不符合预期：期望 %s，实际 %s", n.ExpectExitIP, ip)
	}
	return ip, err
}

func errOf(pr *socks5probe.Result) string {
	if pr == nil {
		return "未知错误"
	}
	if pr.Error != "" {
		return pr.Error
	}
	return "未知错误"
}

// tcpCheckFrom 在远端执行 TCP 连通性检查（白名单命令，参数为 host/port，无用户拼接）。
func tcpCheckFrom(ctx context.Context, client *ssh.Client, host string, port int) error {
	// 纵深防御：即使上游漏校验，也绝不把可疑 host 拼进 shell
	if err := validate.Host(host); err != nil {
		return fmt.Errorf("落地地址不合法: %w", err)
	}
	cmd := fmt.Sprintf(`timeout 6 bash -c 'cat < /dev/null > /dev/tcp/%s/%d' && echo OK || echo FAIL`, host, port)
	o, err := sshx.RunOut(ctx, client, cmd)
	if err != nil || !strings.Contains(o, "OK") {
		alt := fmt.Sprintf(`(command -v curl >/dev/null && curl -s -m 5 -o /dev/null telnet://%s:%d && echo OK) || (command -v nc >/dev/null && nc -z -w5 %s %d && echo OK) || echo FAIL`, host, port, host, port)
		o2, _ := sshx.RunOut(ctx, client, alt)
		if !strings.Contains(o2, "OK") {
			return fmt.Errorf("前置无法连接落地 %s:%d（检查落地防火墙/安全组与端口监听）", host, port)
		}
	}
	return nil
}
