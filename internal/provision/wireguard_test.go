package provision

import (
	"strings"
	"testing"
)

func TestWGIfaceName(t *testing.T) {
	for _, p := range []int{443, 46010, 65535} {
		name := wgIfaceName(p)
		if len(name) > 15 {
			t.Errorf("网卡名超过 15 字符: %q", name)
		}
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				t.Errorf("网卡名含非法字符: %q", name)
			}
		}
	}
	if wgIfaceName(443) == wgIfaceName(46010) {
		t.Error("不同端口不应生成相同网卡名")
	}
}

func TestWGAddrs(t *testing.T) {
	srv, cli := wgAddrs(46010)
	if srv != "10.66.10.1/24" {
		t.Errorf("服务端地址错误: %s", srv)
	}
	if cli != "10.66.10.2/32" {
		t.Errorf("客户端地址错误: %s", cli)
	}
	// 不同端口应落在不同子网（取模 200 内）
	srv2, _ := wgAddrs(46011)
	if srv2 == srv {
		t.Error("不同端口应得到不同子网")
	}
	// 端口 200 的倍数要兜底到 .1 而不是 .0
	srv3, _ := wgAddrs(200)
	if !strings.Contains(srv3, "10.66.1.1/24") {
		t.Errorf("200 端口子网兜底错误: %s", srv3)
	}
}

func TestRenderWGServerConf(t *testing.T) {
	conf := renderWGServerConf(46010, "SERVER_PRIV", "CLIENT_PUB", "10.66.10.1/24", "eth0")
	for _, want := range []string{
		"Address = 10.66.10.1/24",
		"ListenPort = 46010",
		"PrivateKey = SERVER_PRIV",
		"PublicKey = CLIENT_PUB",
		"AllowedIPs = 10.66.10.2/32",
		"MASQUERADE",
		"-o eth0",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("服务端配置缺少 %q\n%s", want, conf)
		}
	}
	// 无私网出口时不应写 NAT 规则
	noNAT := renderWGServerConf(46010, "P", "C", "10.66.10.1/24", "")
	if strings.Contains(noNAT, "MASQUERADE") {
		t.Error("无外网接口时不应生成 NAT 规则")
	}
}

func TestRenderWGClientConf(t *testing.T) {
	conf := renderWGClientConf("1.2.3.4", 46010, "CLIENT_PRIV", "SERVER_PUB", "10.66.10.2/32")
	for _, want := range []string{
		"PrivateKey = CLIENT_PRIV",
		"Address = 10.66.10.2/32",
		"PublicKey = SERVER_PUB",
		"Endpoint = 1.2.3.4:46010",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("客户端配置缺少 %q\n%s", want, conf)
		}
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("abc+/="); got != "'abc+/='" {
		t.Errorf("普通密钥被误处理: %q", got)
	}
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Errorf("单引号未正确转义: %q", got)
	}
}
