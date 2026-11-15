// Package chain 实现「前置 → 落地」的一键链路配置。
//
// 落地统一走 landing.Node 抽象（P2）：
//   - server      : 在落地 VPS 上部署入站，前置用 xray outbound 连它
//   - home_socks5 : 不部署落地，前置直接走 SOCKS5 出站
//
// 全流程只有一处分支（landing.Node 内部），这里不复制第二套流程。
package chain

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/crypto/ssh"

	"vpspanel/internal/landing"
	"vpspanel/internal/provision"
	"vpspanel/internal/sshx"
)

type Params struct {
	RelayPort int    `json:"relay_port"` // 前置对外端口，默认 443
	Dest      string `json:"dest"`
	SNI       string `json:"sni"`
	Tag       string `json:"tag"`
}

type Result struct {
	Logs   []string          `json:"logs"`
	Link   string            `json:"link"`
	Meta   map[string]string `json:"meta"`
	ExitIP string            `json:"exit_ip"`
}

func logfTo(logf func(string)) func(string, ...any) {
	return func(f string, a ...any) {
		if logf != nil {
			logf(fmt.Sprintf(f, a...))
		}
	}
}

type realityKeys struct{ priv, pub string }

func genKeys(ctx context.Context, client *ssh.Client) (realityKeys, error) {
	o, err := sshx.RunOut(ctx, client, "/usr/local/bin/xray x25519 2>/dev/null")
	if err != nil {
		return realityKeys{}, err
	}
	k := realityKeys{
		priv: provision.PickField(o, "(?i)private\\s*key"),
		pub:  provision.PickField(o, "(?i)(?:public\\s*key|password)(?:\\s*\\([^)]*\\))"),
	}
	if k.priv == "" || k.pub == "" {
		return realityKeys{}, fmt.Errorf("无法解析 x25519 输出")
	}
	return k, nil
}

// Deploy 部署链路。landingClient 仅在 node.Kind == KindServer 时必填。
func Deploy(ctx context.Context, relay *ssh.Client, relayHost string,
	node *landing.Node, landingClient *ssh.Client, p Params, logf func(string)) (*Result, error) {

	add := logfTo(logf)
	res := &Result{Meta: map[string]string{}}

	if p.RelayPort == 0 {
		p.RelayPort = provision.DefaultPort
	}
	if p.Dest == "" {
		p.Dest = "www.microsoft.com:443"
	}
	if p.SNI == "" {
		p.SNI = strings.Split(p.Dest, ":")[0]
	}
	if p.Tag == "" {
		p.Tag = fmt.Sprintf("chain-%d", p.RelayPort)
	}
	if node == nil {
		return nil, fmt.Errorf("缺少落地节点")
	}
	if node.Kind == landing.KindServer && landingClient == nil {
		return nil, fmt.Errorf("缺少落地 VPS 的连接")
	}

	landingDeployed := false
	relayDeployed := false
	rollback := func() {
		if relayDeployed {
			_ = provision.Uninstall(ctx, relay, "chain-relay", p.RelayPort, logf)
		}
		if landingDeployed && landingClient != nil {
			_ = provision.Uninstall(ctx, landingClient, "chain-landing", node.Port, logf)
		}
	}

	// ── 1. 落地：只有 server 型需要部署 ──
	if node.Kind == landing.KindServer {
		add("【落地】%s 准备环境…", node.Label())
		if err := provision.Prepare(ctx, landingClient, node.Port, logf); err != nil {
			return nil, fmt.Errorf("落地准备失败: %w", err)
		}
		node.UUID = provision.NewUUID()
		if node.Protocol == "" {
			node.Protocol = "vless-reality"
		}
		if node.Protocol == "vmess-ws" {
			node.Path = "/" + strings.ReplaceAll(provision.NewUUID(), "-", "")[:8]
		} else {
			keys, err := genKeys(ctx, landingClient)
			if err != nil {
				return nil, fmt.Errorf("落地生成 Reality 密钥失败: %w", err)
			}
			node.PrivKey, node.PubKey = keys.priv, keys.pub
			node.ShortID = provision.NewUUID()[:8]
			node.SNI, node.Dest = p.SNI, p.Dest
		}
		in, err := node.Inbound()
		if err != nil {
			return nil, err
		}
		cfg, err := provision.BuildConfig([]any{in}, []any{provision.FreedomOutbound("direct")})
		if err != nil {
			return nil, err
		}
		add("【落地】写入配置并启动 (:%d)…", node.Port)
		if err := provision.Install(ctx, landingClient, node.Port, cfg, logf); err != nil {
			return nil, fmt.Errorf("落地部署失败: %w", err)
		}
		landingDeployed = true
	} else {
		add("【落地】%s（无需在 VPS 上部署，前置直接走 SOCKS5 出站）", node.Label())
	}

	// ── 2. 前置 ──
	add("【前置】%s 准备环境…", relayHost)
	if err := provision.Prepare(ctx, relay, p.RelayPort, logf); err != nil {
		rollback()
		return nil, fmt.Errorf("前置准备失败: %w", err)
	}
	rKeys, err := genKeys(ctx, relay)
	if err != nil {
		rollback()
		return nil, fmt.Errorf("前置生成 Reality 密钥失败: %w", err)
	}
	rUUID := provision.NewUUID()
	rShort := provision.NewUUID()[:8]

	out, err := node.Outbound("to-landing")
	if err != nil {
		rollback()
		return nil, fmt.Errorf("生成落地出站失败: %w", err)
	}
	relayIn := provision.RealityInbound(p.RelayPort, rUUID, rKeys.priv, rShort, p.Dest, p.SNI)
	relayCfg, err := provision.BuildConfig([]any{relayIn}, []any{out, provision.FreedomOutbound("direct")})
	if err != nil {
		rollback()
		return nil, err
	}
	add("【前置】写入配置并启动 (:%d)…", p.RelayPort)
	if err := provision.Install(ctx, relay, p.RelayPort, relayCfg, logf); err != nil {
		rollback()
		return nil, fmt.Errorf("前置部署失败: %w", err)
	}
	relayDeployed = true

	// ── 3. 统一链路测试：可达性 → 出口 IP（类型分支只在 landing.Node 内部）──
	add("【测试】落地可达性…")
	if err := node.Reachable(ctx, relay); err != nil {
		add("✗ %v", err)
		rollback()
		return nil, fmt.Errorf("链路测试失败（已回滚）: %w", err)
	}
	add("✓ 落地可达")

	add("【测试】出口 IP…")
	exitIP, ipErr := node.ExitIP(ctx, landingClient)
	if ipErr != nil {
		add("✗ %v", ipErr)
		rollback()
		return nil, fmt.Errorf("出口校验失败（已回滚）: %w", ipErr)
	}
	res.ExitIP = exitIP
	if exitIP == "" {
		add("· 未取到出口 IP（未设置预期值，跳过比对）")
	} else {
		add("✓ 出口 IP: %s", exitIP)
	}

	// ── 4. 客户端链接（指向前置）──
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("type", "tcp")
	q.Set("security", "reality")
	q.Set("sni", p.SNI)
	q.Set("fp", "chrome")
	q.Set("pbk", rKeys.pub)
	q.Set("sid", rShort)
	q.Set("flow", "xtls-rprx-vision")
	res.Link = fmt.Sprintf("vless://%s@%s:%d?%s#%s", rUUID, relayHost, p.RelayPort, q.Encode(), url.QueryEscape(p.Tag))

	res.Meta["relay"] = fmt.Sprintf("%s:%d", relayHost, p.RelayPort)
	res.Meta["landing_kind"] = string(node.Kind)
	res.Meta["landing"] = node.Label()
	res.Meta["relay_uuid"] = rUUID
	res.Meta["relay_pbk"] = rKeys.pub
	res.Meta["relay_sid"] = rShort
	return res, nil
}
