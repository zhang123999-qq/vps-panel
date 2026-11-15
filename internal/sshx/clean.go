// 本文件负责把 SSH 原始输出洗成「可安全放进表格单元格」的值。
//
// 背景：远端 SSH 可能被 MOTD / 登录告警污染，例如：
//
//	Could not chdir to home directory /root: No such file or directory
//	Debian GNU/Linux 12 (bookworm)
//	Last login: ...
//
// 这些多行文本一旦直接进 JSON，前端表格会被撑破，列也会错位。
// 因此所有对外字段统一经过：去 ANSI → 去 CR → 按行切分 → 去噪声行 → 单行化 → 截断。
package sshx

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	ctrlRe   = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	spaceRe  = regexp.MustCompile(`\s+`)
	promptRe = regexp.MustCompile(`(?m)^[\w.@\-]+:.*[$#]\s*$`)
)

// noiseMarkers 是明确不属于系统信息的行（MOTD/登录告警/免责声明等）。
var noiseMarkers = []string{
	"could not chdir",
	"permission denied",
	"last login",
	"last failed login",
	"there were",
	"failed login attempt",
	"warning:",
	"warnings:",
	"motd",
	"message of the day",
	"system information",
	"system load",
	"usage of",
	"usage on",
	"swap usage",
	"processes:",
	"users logged in",
	"ipv4 address for",
	"ipv6 address for",
	"authorized uses only",
	"disclaimer",
	"welcome to",
	"documentation:",
	"management:",
	"support:",
	"*** ",
	"restricted access",
}

// 常见发行版关键字，用于在噪声中挑出真正的 OS 名称。
var distroMarkers = []string{
	"gnu/linux", "ubuntu", "debian", "centos", "almalinux", "rocky", "fedora",
	"arch linux", "alpine", "opensuse", "suse", "oracle linux", "amazon linux",
	"kylin", "anolis", "tencentos", "opencloudos", "euleros", "openeuler",
	"deepin", "uos", "raspbian", "linux mint", "freebsd", "openbsd", "netbsd",
	"windows", "alibaba cloud linux",
}

// StripANSI 去掉终端颜色/控制序列。
func StripANSI(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	return ctrlRe.ReplaceAllString(s, "")
}

// Sanitize 把任意原始输出压成「单行、无控制字符、空白折叠」的安全字符串。
// 结果一定不含 \n / \r / \t，可直接放进表格单元格或日志。
func Sanitize(s string) string {
	s = StripANSI(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = spaceRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// Truncate 按 rune 截断，避免切坏多字节字符。
func Truncate(s string, max int) string {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max]) + "…"
}

func splitLines(raw string) []string {
	raw = StripANSI(raw)
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	return strings.Split(raw, "\n")
}

// hasDistro 判断这一行是否明确是发行版名称（优先级高于噪声过滤）。
func hasDistro(line string) bool {
	l := strings.ToLower(line)
	for _, d := range distroMarkers {
		if strings.Contains(l, d) {
			return true
		}
	}
	return false
}

func isNoise(line string) bool {
	l := strings.ToLower(strings.TrimSpace(line))
	if l == "" {
		return true
	}
	// 含发行版关键字的行优先保留（"Welcome to Ubuntu 22.04.3 LTS" 就是有效信息）
	if hasDistro(l) {
		return false
	}
	if promptRe.MatchString(line) {
		return true
	}
	for _, m := range noiseMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

func distroScore(line string) int {
	l := strings.ToLower(line)
	score := 0
	for _, d := range distroMarkers {
		if strings.Contains(l, d) {
			score += 10
			break
		}
	}
	if strings.Contains(l, "gnu/linux") {
		score += 5
	}
	if strings.ContainsAny(line, "0123456789") {
		score += 3
	}
	if strings.Contains(line, "(") && strings.Contains(line, ")") {
		score += 2
	}
	if len(line) > 64 {
		score -= 5
	}
	// 形如 "Linux 5.15.0-91-generic" 的核信息不是发行版名
	if strings.HasPrefix(l, "linux ") {
		score -= 8
	}
	return score
}

// OSName 从可能被污染的原始输出中提取干净的发行版名称。
// 提取失败返回空串（由调用方决定显示 "未知" 还是判失败）。
func OSName(raw string) string {
	best, bestScore := "", 0
	for _, line := range splitLines(raw) {
		line = Sanitize(line)
		if isNoise(line) {
			continue
		}
		if sc := distroScore(line); sc > bestScore {
			best, bestScore = line, sc
		}
	}
	if best == "" {
		return ""
	}
	// 去掉 MOTD 常见前缀，让单元格更紧凑
	for _, pfx := range []string{"welcome to ", "welcome, ", "welcome "} {
		if len(best) > len(pfx) && strings.EqualFold(best[:len(pfx)], pfx) {
			best = best[len(pfx):]
			break
		}
	}
	return Truncate(strings.TrimSpace(best), 64)
}

// OneLine 取第一行有效内容（用于 kernel / 架构等短字段）。
func OneLine(raw string) string {
	for _, line := range splitLines(raw) {
		line = Sanitize(line)
		if line != "" && !isNoise(line) {
			return Truncate(line, 80)
		}
	}
	return ""
}

// Specs 生成「规格」列的单行文本，例如 "4 核 / 11884 MB / 105 GB"。
func Specs(cores, memMB, diskGB int) string {
	parts := make([]string, 0, 3)
	if cores > 0 {
		parts = append(parts, itoa(cores)+" 核")
	}
	if memMB > 0 {
		parts = append(parts, itoa(memMB)+" MB")
	}
	if diskGB > 0 {
		parts = append(parts, itoa(diskGB)+" GB")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " / ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
