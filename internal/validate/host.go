// Package validate 收敛所有「会进入远端命令或配置」的输入校验。
//
// 为什么单独成包：
//   - 主机名会被拼进 `/dev/tcp/<host>/<port>` 这类 shell 片段（P0 命令注入面）；
//   - 端口、协议名、路径也会进入命令或文件名；
//   - 校验必须被 API 层与执行层**同时**调用（纵深防御），所以放在谁都能引用的位置。
package validate

import (
	"fmt"
	"regexp"
	"strings"
)

// hostRe 只允许：字母、数字、点、横线、下划线、冒号、IPv6 方括号。
// 明确排除 空格 / 分号 / 反引号 / $ / | / & / 引号 / 斜杠 / 换行。
var hostRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]{1,253}$`)

// Host 校验主机字段（IP / 域名 / IPv6）。
func Host(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("地址不能为空")
	}
	if !hostRe.MatchString(s) {
		return fmt.Errorf("地址格式不合法（只允许字母、数字、点、横线、下划线、冒号、方括号）")
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("地址格式不合法")
	}
	return nil
}

// Port 校验端口范围。
func Port(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("端口需在 1-65535 之间（当前 %d）", p)
	}
	return nil
}

// Protocol 校验协议名（白名单，避免拼进文件名/服务名）。
func Protocol(p string) error {
	switch p {
	case "vless", "vmess", "trojan", "hysteria2", "wireguard", "shadowsocks", "socks", "http", "chain", "residential":
		return nil
	}
	return fmt.Errorf("不支持的协议: %s", p)
}

// ShellSafeToken 断言字符串不含 shell 元字符（用于必须进命令的短标识）。
func ShellSafeToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':' || r == '[' || r == ']':
		default:
			return false
		}
	}
	return true
}
