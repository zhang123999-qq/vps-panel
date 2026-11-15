// WireGuard 接入（第 8 种协议）。
//
// 与 xray/sing-box 不同，WireGuard 走系统内核模块 + wg-quick，因此：
//   - 远端必须已有 wireguard-tools（缺失时给出可执行的安装提示，而不是笼统报错）；
//   - 服务由 `wg-quick up <iface>` 拉起，systemd 单元只作为守护；
//   - 客户端拿到的是标准 INI 配置（WireGuard 没有官方 URI scheme）。
package provision

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"vpspanel/internal/netcheck"
	"vpspanel/internal/sshx"
)

// wgIfaceName 生成合法网卡名（<=15 字符，仅字母数字）。
func wgIfaceName(port int) string {
	return fmt.Sprintf("wgvp%d", port)
}

// wgAddrs 由端口推导一个稳定的 /24 子网，避免多实例冲突。
// 例：端口 46010 -> idx=10 -> 服务端 10.66.10.1/24，客户端 10.66.10.2/32
func wgAddrs(port int) (server string, client string) {
	idx := port % 200
	if idx == 0 {
		idx = 1
	}
	return fmt.Sprintf("10.66.%d.1/24", idx), fmt.Sprintf("10.66.%d.2/32", idx)
}

// ensureWireguardTools 检查远端是否有 wg / wg-quick；没有就给出安装命令。
func ensureWireguardTools(ctx context.Context, client *ssh.Client) error {
	wg, _ := sshx.RunOut(ctx, client, "command -v wg 2>/dev/null")
	wgq, _ := sshx.RunOut(ctx, client, "command -v wg-quick 2>/dev/null")
	var missing []string
	if strings.TrimSpace(wg) == "" {
		missing = append(missing, "wg")
	}
	if strings.TrimSpace(wgq) == "" {
		missing = append(missing, "wg-quick")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("远端缺少 wireguard-tools（%s）。请先在目标机执行：\n"+
		"  Debian/Ubuntu: apt update && apt install -y wireguard\n"+
		"  CentOS/RHEL:   yum install -y wireguard-tools\n"+
		"  然后重新部署", strings.Join(missing, ", "))
}

// genWGKey 生成一对 WireGuard 密钥（私钥/公钥）。
func genWGKey(ctx context.Context, client *ssh.Client) (priv, pub string, err error) {
	p, err := sshx.RunOut(ctx, client, "wg genkey 2>/dev/null")
	if err != nil || strings.TrimSpace(p) == "" {
		return "", "", fmt.Errorf("生成 WireGuard 私钥失败: %v", err)
	}
	priv = strings.TrimSpace(p)
	q, err := sshx.RunOut(ctx, client, fmt.Sprintf("printf '%%s' %s | wg pubkey 2>/dev/null", shellQuote(priv)))
	if err != nil || strings.TrimSpace(q) == "" {
		return "", "", fmt.Errorf("派生 WireGuard 公钥失败: %v", err)
	}
	return priv, strings.TrimSpace(q), nil
}

// shellQuote 单引号转义（密钥字符集固定为 base64，仅防御性使用）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// renderWGServerConf 生成服务端配置。
func renderWGServerConf(port int, serverPriv, clientPub, serverAddr, extIface string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", serverAddr)
	fmt.Fprintf(&b, "ListenPort = %d\n", port)
	fmt.Fprintf(&b, "PrivateKey = %s\n", serverPriv)
	if extIface != "" {
		fmt.Fprintf(&b, "PostUp = sysctl -w net.ipv4.ip_forward=1\n")
		fmt.Fprintf(&b, "PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", extIface)
		fmt.Fprintf(&b, "PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n", extIface)
	}
	fmt.Fprintf(&b, "\n[Peer]\n# client\nPublicKey = %s\nAllowedIPs = %s\n", clientPub, strings.Replace(serverAddr, ".1/24", ".2/32", 1))
	return b.String()
}

// renderWGClientConf 生成客户端配置（可直接导入 WireGuard 官方客户端）。
func renderWGClientConf(endpoint string, port int, clientPriv, serverPub, clientAddr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1, 8.8.8.8\n\n", clientPriv, clientAddr)
	fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		serverPub, endpoint, port)
	return b.String()
}

// DeployWireGuard 部署一个 WireGuard 服务端，返回客户端配置。
func DeployWireGuard(ctx context.Context, client *ssh.Client, host string, spec *Spec, logf func(string)) (*Result, error) {
	add := logger(logf)
	res := &Result{Meta: map[string]string{}}

	if err := ensureWireguardTools(ctx, client); err != nil {
		return nil, err
	}
	if err := Prepare(ctx, client, spec.Port, logf); err != nil {
		return nil, err
	}

	sPriv, sPub, err := genWGKey(ctx, client)
	if err != nil {
		return nil, err
	}
	cPriv, cPub, err := genWGKey(ctx, client)
	if err != nil {
		return nil, err
	}
	serverAddr, clientAddr := wgAddrs(spec.Port)

	ext, _ := sshx.RunOut(ctx, client, "ip route show default 2>/dev/null | awk '{print $5; exit}'")
	extIface := strings.TrimSpace(ext)

	iface := wgIfaceName(spec.Port)
	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", iface)
	conf := renderWGServerConf(spec.Port, sPriv, cPub, serverAddr, extIface)
	priv := sshx.DetectPrivilege(ctx, client)
	if err := priv.Check(); err != nil {
		add("✗ 权限不足：%v", err)
		return nil, err
	}
	if err := writeFilePriv(client, priv, confPath, []byte(conf), "0600"); err != nil {
		return nil, fmt.Errorf("写入 WireGuard 配置失败: %w", err)
	}
	add("✓ 配置已写入 %s (0600)", confPath)

	// 幂等：已存在则先 down
	_, _ = sshx.RunOut(ctx, client, priv.Wrap(fmt.Sprintf("wg-quick down %s 2>/dev/null || true", iface)))
	if _, err := sshx.RunOut(ctx, client, priv.Wrap(fmt.Sprintf("wg-quick up %s 2>&1", iface))); err != nil {
		out, _ := sshx.RunOut(ctx, client, priv.Wrap(fmt.Sprintf("wg-quick up %s 2>&1", iface)))
		add("  %s", sshx.Brief(out, 600))
		return nil, fmt.Errorf("wg-quick up 失败（%s）: %v", firstNonEmpty(sshx.Classify(out), "见日志"), err)
	}
	add("✓ wg-quick 已启动 %s", iface)

	ok := false
	for i := 0; i < 8; i++ {
		if busy, _, e := netcheck.InUse(ctx, client, spec.Port); e == nil && busy {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("WireGuard 未监听 UDP %d（检查内核模块：modprobe wireguard）", spec.Port)
	}
	add("✓ UDP %d 正在监听", spec.Port)

	OpenFirewall(ctx, client, spec.Port, "udp", logf)

	clientConf := renderWGClientConf(host, spec.Port, cPriv, sPub, clientAddr)
	res.Config = conf
	res.Meta["iface"] = iface
	res.Meta["server_pub"] = sPub
	res.Meta["client_addr"] = clientAddr
	res.Meta["client_config"] = clientConf
	// WireGuard 无标准 URI，节点"链接"位直接给出客户端 INI，便于整段复制
	res.Link = clientConf
	return res, nil
}

// UninstallWireGuard 关闭并删除接口与配置。
func UninstallWireGuard(ctx context.Context, client *ssh.Client, port int, logf func(string)) error {
	iface := wgIfaceName(port)
	_, _ = sshx.RunOut(ctx, client, fmt.Sprintf("wg-quick down %s 2>/dev/null || true", iface))
	_, _ = sshx.RunOut(ctx, client, fmt.Sprintf("rm -f /etc/wireguard/%s.conf", iface))
	logger(logf)("✓ 已移除 WireGuard 接口 %s", iface)
	return nil
}
