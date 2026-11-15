package sshx

import (
	"strings"
	"testing"
)

// 真实场景：SSH 登录时 MOTD / chdir 告警被混进 stdout。
const polluted = "\x1b[33mCould not chdir to home directory /root: No such file or directory\x1b[0m\n" +
	"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n" +
	"\n" +
	" * Documentation:  https://help.ubuntu.com\n" +
	" * Management:     https://landscape.canonical.com\n" +
	" * Support:        https://ubuntu.com/advantage\n" +
	"\n" +
	"  System information as of Mon Nov 15 05:00:00 UTC 2026\n" +
	"  System load:  0.08\n" +
	"  Usage of /:   23.1% of 39.16GB\n" +
	"Last login: Sun Nov 15 04:59:12 2026 from 10.0.0.2\n"

func TestSanitizeRemovesNewlines(t *testing.T) {
	got := Sanitize(polluted)
	if strings.ContainsAny(got, "\r\n\t") {
		t.Fatalf("Sanitize 仍含换行/制表符: %q", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("ANSI 未清理: %q", got)
	}
}

func TestOSNamePicksCleanDistro(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"debian 纯净", "Debian GNU/Linux 12 (bookworm)\n", "Debian GNU/Linux 12 (bookworm)"},
		{"被 MOTD 污染", polluted, "Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)"},
		{"chdir 只有噪声", "Could not chdir to home directory /root: No such file or directory\n", ""},
		{"centos", "CentOS Linux 7 (Core)\n", "CentOS Linux 7 (Core)"},
		{"alpine", "Alpine Linux v3.19\n", "Alpine Linux v3.19"},
		{"空输入", "", ""},
		{"只有内核行", "Linux 5.15.0-91-generic\n", ""},
	}
	for _, c := range cases {
		if got := OSName(c.in); got != c.want {
			t.Errorf("%s: OSName()=%q want %q", c.name, got, c.want)
		}
	}
}

func TestOSNameNeverReturnsNewline(t *testing.T) {
	got := OSName(polluted)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("OSName 返回了多行: %q", got)
	}
	if len([]rune(got)) > 64 {
		t.Fatalf("OSName 未截断: %d 字符", len([]rune(got)))
	}
}

func TestOneLine(t *testing.T) {
	if got := OneLine("  \n 11884 \n"); got != "11884" {
		t.Fatalf("OneLine()=%q", got)
	}
	if got := OneLine("Could not chdir to home directory /root\n"); got != "" {
		t.Fatalf("OneLine 应过滤噪声，得到 %q", got)
	}
}

func TestSpecs(t *testing.T) {
	if got := Specs(4, 11884, 105); got != "4 核 / 11884 MB / 105 GB" {
		t.Fatalf("Specs()=%q", got)
	}
	if got := Specs(0, 0, 0); got != "" {
		t.Fatalf("Specs 空值应为空串，得到 %q", got)
	}
	if got := Specs(2, 0, 40); got != "2 核 / 40 GB" {
		t.Fatalf("Specs 缺项处理错误: %q", got)
	}
}

func TestTruncateRune(t *testing.T) {
	got := Truncate("中文系统名称很长很长很长", 5)
	if []rune(got)[len([]rune(got))-1] != '…' {
		t.Fatalf("Truncate 未加省略号: %q", got)
	}
}
