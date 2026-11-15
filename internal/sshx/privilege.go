// 权限探测与错误归类。
//
// 现实问题：面板常以普通用户（如 next）登录 VPS，写 /usr/local/bin、
// /etc/systemd/system 需要 root。若直接执行 install/mv，会以
// "Permission denied" 或 "sudo: a terminal is required" 失败，
// 而旧代码把 stderr 丢弃了，前端只能看到「安装失败，已回滚」。
package sshx

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Privilege 描述远端当前会话的权限能力。
type Privilege struct {
	User   string // 当前登录用户
	IsRoot bool   // uid == 0
	Sudo   bool   // 免密 sudo 可用（sudo -n true 成功）
}

// DetectPrivilege 探测当前用户与免密 sudo 能力。
// 失败不返回 error：拿不到信息时按「非 root、无 sudo」处理，后续会给出明确提示。
func DetectPrivilege(ctx context.Context, client *ssh.Client) Privilege {
	p := Privilege{}
	if u, err := RunOut(ctx, client, "id -un 2>/dev/null"); err == nil {
		p.User = Sanitize(u)
	}
	if uid, err := RunOut(ctx, client, "id -u 2>/dev/null"); err == nil {
		p.IsRoot = strings.TrimSpace(uid) == "0"
	}
	if !p.IsRoot {
		// -n：非交互；不可用时不会挂住，直接失败
		if _, err := RunOut(ctx, client, "sudo -n true 2>/dev/null"); err == nil {
			p.Sudo = true
		}
	}
	return p
}

// NeedSudo 是否需要给命令加 sudo 前缀。
func (p Privilege) NeedSudo() bool { return !p.IsRoot }

// Wrap 为需要 root 的命令加前缀。非 root 时用 `sudo -n`（不交互，缺权限立刻失败）。
func (p Privilege) Wrap(cmd string) string {
	if !p.NeedSudo() {
		return cmd
	}
	return "sudo -n " + cmd
}

// Check 判断是否具备写系统路径的能力；不具备时返回可直接展示给用户的错误。
func (p Privilege) Check() error {
	if p.IsRoot {
		return nil
	}
	if p.Sudo {
		return nil
	}
	user := p.User
	if user == "" {
		user = "当前用户"
	}
	return fmt.Errorf("当前用户 %s 无 root 权限，且缺少 sudo 免密配置。"+
		"请任选其一：① 在面板里改用 root 账号；② 在该机为 %s 配置 NOPASSWD sudo"+
		"（/etc/sudoers.d/vpspanel: `%s ALL=(ALL) NOPASSWD: ALL`）；"+
		"③ 手动把内核与配置放到目标路径后重试", user, user, user)
}

// Classify 从命令输出/错误里提炼「人话」原因，便于前端一眼定位。
// 覆盖用户明确要求区分的三类：Permission denied / command not found / Exec format error。
func Classify(out string) string {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "a terminal is required"), strings.Contains(l, "a password is required"),
		strings.Contains(l, "password is required"):
		return "缺少 sudo 免密（sudo 要求输入密码或终端）"
	case strings.Contains(l, "permission denied"), strings.Contains(l, "operation not permitted"):
		return "权限不足（Permission denied），当前用户无法写入系统路径"
	case strings.Contains(l, "exec format error"), strings.Contains(l, "cannot execute binary file"):
		return "内核架构与目标机不符或文件损坏（Exec format error）"
	case strings.Contains(l, "command not found"), strings.Contains(l, "not found"):
		return "命令不存在（command not found），目标机可能缺少基础工具"
	case strings.Contains(l, "no space left"):
		return "目标机磁盘已满（No space left on device）"
	case strings.Contains(l, "text file busy"):
		return "内核文件正被占用（Text file busy），请先停止该节点服务"
	case strings.Contains(l, "read-only file system"):
		return "目标路径只读（Read-only file system）"
	}
	return ""
}

// Brief 把多行输出压成一行便于放进错误信息（保留关键行）。
func Brief(out string, max int) string {
	s := Sanitize(out)
	if s == "" {
		return "（无输出）"
	}
	if max > 0 && len([]rune(s)) > max {
		return Truncate(s, max)
	}
	return s
}
