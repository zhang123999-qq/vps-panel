package provision

import "testing"

// 回归：SSH 登录告警曾被合并进 stdout，导致 `command -v ufw` 被判为「已安装」。
func TestDecideFirewallIgnoresPollutedOutput(t *testing.T) {
	const noise = "Could not chdir to home directory /home/next: No such file or directory x86_64"

	cases := []struct {
		name                             string
		ufwPath, ufwStatus, fwPath, fwSt string
		want                             FirewallKind
	}{
		{"ufw 启用", "/usr/sbin/ufw", "Status: active", "", "", FWUfw},
		{"ufw 未启用", "/usr/sbin/ufw", "Status: inactive", "", "", FWNone},
		{"ufw 输出被污染（无路径）", noise, "", "", "", FWNone},
		{"ufw 状态行被污染但确实 active", "/usr/sbin/ufw", "Status: active", "", "", FWUfw},
		{"firewalld 运行中", "", "", "/usr/bin/firewall-cmd", "running", FWFirewalld},
		{"firewalld 未运行", "", "", "/usr/bin/firewall-cmd", "not running", FWNone},
		{"两者都没有", "", "", "", "", FWNone},
		{"都有时优先 ufw", "/usr/sbin/ufw", "Status: active", "/usr/bin/firewall-cmd", "running", FWUfw},
		{"路径含换行视为无效", "/usr/sbin/ufw\nCould not chdir", "Status: active", "", "", FWNone},
	}
	for _, c := range cases {
		if got := decideFirewall(c.ufwPath, c.ufwStatus, c.fwPath, c.fwSt); got != c.want {
			t.Errorf("%s: decideFirewall()=%q want %q", c.name, got, c.want)
		}
	}
}

func TestLooksLikePath(t *testing.T) {
	ok := []string{"/usr/sbin/ufw", "/usr/bin/firewall-cmd"}
	bad := []string{"", "Could not chdir to home directory /home/next", "ufw not found", "/usr/bin/x\nnoise"}
	for _, s := range ok {
		if !looksLikePath(s) {
			t.Errorf("应识别为路径: %q", s)
		}
	}
	for _, s := range bad {
		if looksLikePath(s) {
			t.Errorf("不应识别为路径: %q", s)
		}
	}
}

func TestCleanArch(t *testing.T) {
	cases := map[string]string{
		"x86_64\n": "x86_64",
		"Could not chdir to home directory /home/next: No such file or directory x86_64\n": "x86_64",
		"aarch64\n": "aarch64",
		"Could not chdir to home directory /home/next: No such file or directory\n": "Could not chdir to home directory /home/next: No such file or directory",
	}
	for in, want := range cases {
		if got := cleanArch(in); got != want {
			t.Errorf("cleanArch(%q)=%q want %q", in, got, want)
		}
	}
}
