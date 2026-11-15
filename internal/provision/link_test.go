package provision

import (
	"net/url"
	"strings"
	"testing"
)

// URI 编码回归：密码/路径里出现 @ / ? # 等字符时，链接必须可被标准客户端解析。
func TestBuildLinkEncoding(t *testing.T) {
	pw := "p@ss/word?x=1#frag 空格"

	// Trojan：密码需 URL 编码，解析后应还原
	tro := &Spec{Protocol: "trojan", Port: 8443, Tag: "节点 A", Password: pw}
	link := buildLink("1.2.3.4", tro)
	if strings.Contains(link, pw) {
		t.Fatalf("Trojan 链接未编码密码: %s", link)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("Trojan 链接无法解析: %v (%s)", err, link)
	}
	if u.User.Username() != pw {
		t.Errorf("Trojan 密码解码不一致: got %q want %q", u.User.Username(), pw)
	}
	if _, hasPwd := u.User.Password(); hasPwd {
		t.Errorf("Trojan 链接不应带空密码段: %s", link)
	}
	if u.Host != "1.2.3.4:8443" {
		t.Errorf("host 解析错误: %s", u.Host)
	}

	// Hysteria2：同样规则
	hy := &Spec{Protocol: "hysteria2", Port: 443, Tag: "hy2", Password: pw}
	hlink := buildLink("1.2.3.4", hy)
	if strings.Contains(hlink, pw) {
		t.Fatalf("Hysteria2 链接未编码密码: %s", hlink)
	}
	if hu, err := url.Parse(hlink); err != nil || hu.User.Username() != pw {
		t.Errorf("Hysteria2 密码解码不一致: %v %q", err, hlink)
	}

	// Shadowsocks：userinfo 用 base64url，@ 与 / 不会破坏结构
	ss := &Spec{Protocol: "shadowsocks", Port: 8388, Tag: "ss", Method: "aes-256-gcm", Password: pw}
	slink := buildLink("1.2.3.4", ss)
	surl, err := url.Parse(slink)
	if err != nil {
		t.Fatalf("SS 链接无法解析: %v (%s)", err, slink)
	}
	if surl.Host != "1.2.3.4:8388" {
		t.Errorf("SS host 解析错误: %s", surl.Host)
	}

	// VLESS+WS：path 含特殊字符也要正确编码
	vl := &Spec{Protocol: "vless", Port: 443, Tag: "v", UUID: "11111111-2222-3333-4444-555555555555",
		Network: "ws", Path: "/a b?c=d", PubKey: "PUB", ShortID: "abcd", SNI: "example.com"}
	vlink := buildLink("1.2.3.4", vl)
	vu, err := url.Parse(vlink)
	if err != nil {
		t.Fatalf("VLESS 链接无法解析: %v", err)
	}
	if got := vu.Query().Get("path"); got != "/a b?c=d" {
		t.Errorf("VLESS path 编码不一致: %q", got)
	}
	if vu.Fragment != "v" {
		t.Errorf("VLESS 备注被破坏: %q", vu.Fragment)
	}
}
