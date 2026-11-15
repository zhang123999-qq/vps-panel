package kernel

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"vpspanel/internal/sshx"
)

// Status 读取远端已安装的内核版本（未安装返回空串）。
func Status(ctx context.Context, client *ssh.Client) (xrayVer, sboxVer string) {
	if o, err := sshx.RunOut(ctx, client, "/usr/local/bin/xray version 2>/dev/null | head -1"); err == nil {
		xrayVer = parseXrayVersion(o)
	}
	if o, err := sshx.RunOut(ctx, client, "/usr/local/bin/sing-box version 2>/dev/null | head -1"); err == nil {
		sboxVer = parseSingboxVersion(o)
	}
	return
}

func parseXrayVersion(s string) string {
	// "Xray 26.11.9 (Xray, Penetrates Everything.) ..."
	f := strings.Fields(s)
	if len(f) >= 2 && strings.EqualFold(f[0], "xray") {
		return strings.TrimPrefix(f[1], "v")
	}
	return ""
}

func parseSingboxVersion(s string) string {
	// "sing-box version 1.14.4"
	f := strings.Fields(s)
	for i, x := range f {
		if strings.EqualFold(x, "version") && i+1 < len(f) {
			return strings.TrimPrefix(f[i+1], "v")
		}
	}
	return ""
}

// EnsureRemoteArch 确认远端架构与内嵌资源一致（当前只内嵌 amd64）。
func EnsureRemoteArch(ctx context.Context, client *ssh.Client) error {
	o, err := sshx.RunOut(ctx, client, "uname -m")
	if err != nil {
		return fmt.Errorf("读取架构失败: %w", err)
	}
	a := strings.TrimSpace(o)
	if !strings.Contains(a, "x86_64") && !strings.Contains(a, "amd64") {
		return fmt.Errorf("内嵌内核仅支持 x86_64(amd64)，当前远端为 %s；如需 arm64 请维护者用 scripts/update-kernels.sh --arch arm64 重新构建 exe", a)
	}
	return nil
}

// EnsureXray 确保远端 xray 与内嵌版本一致。已一致则直接返回（幂等）。
func EnsureXray(ctx context.Context, client *ssh.Client, logf func(string)) (string, string, error) {
	old := ""
	if o, err := sshx.RunOut(ctx, client, "/usr/local/bin/xray version 2>/dev/null | head -1"); err == nil {
		old = parseXrayVersion(o)
	}
	if old == XrayVersion {
		return old, old, nil
	}
	return installKernel(ctx, client, "xray", XrayGz(), XrayVersion, old, logf)
}

// EnsureSingbox 确保远端 sing-box 与内嵌版本一致。
func EnsureSingbox(ctx context.Context, client *ssh.Client, logf func(string)) (string, string, error) {
	old := ""
	if o, err := sshx.RunOut(ctx, client, "/usr/local/bin/sing-box version 2>/dev/null | head -1"); err == nil {
		old = parseSingboxVersion(o)
	}
	if old == SingboxVersion {
		return old, old, nil
	}
	return installKernel(ctx, client, "sing-box", SingboxGz(), SingboxVersion, old, logf)
}

// installKernel 是内核安装的唯一入口：上传 → 校验 → 备份 → 安装 → 复核。
//
// 关键约束（对应线上事故）：
//   - 上传只写到 /tmp（普通用户可写），绝不直接写 /usr/local/bin；
//   - 每一步的 stdout/stderr **原样回传日志**，失败时给出可读原因
//     （Permission denied / command not found / Exec format error / sudo 缺免密）；
//   - 回滚过程也打印日志，不再静默。
func installKernel(ctx context.Context, client *ssh.Client, name string, gz []byte, wantVer, oldVer string, logf func(string)) (string, string, error) {
	add := logfTo(logf)
	binPath := "/usr/local/bin/" + name
	stage := "/tmp/" + name + "_upload"
	stageGz := stage + ".gz"

	// ── 0. 权限预检：先判定再传文件，避免白传十几 MB ──
	priv := sshx.DetectPrivilege(ctx, client)
	add("· 远端用户: %s（root=%v，免密sudo=%v）", firstNonEmptyStr(priv.User, "未知"), priv.IsRoot, priv.Sudo)
	if err := priv.Check(); err != nil {
		add("✗ 权限不足：%v", err)
		return oldVer, "", err
	}

	// ── 1. 上传到 /tmp ──
	add("→ 推送内嵌 %s v%s（约 %d MB）", name, wantVer, len(gz)>>20)
	if err := uploadGz(client, gz, stageGz, add); err != nil {
		add("✗ 上传失败：%v", err)
		return oldVer, "", fmt.Errorf("上传内核失败: %w", err)
	}
	add("✓ 已上传: %s", stageGz)

	// ── 2. 解压 + 赋权 + 版本自检（stdout/stderr 全量回传） ──
	verifyCmd := fmt.Sprintf("gunzip -f -c %s > %s && chmod 0755 %s && %s version 2>&1 | head -3",
		stageGz, stage, stage, stage)
	out, err := sshx.Run(ctx, client, verifyCmd)
	add("$ %s", verifyCmd)
	add("  %s", sshx.Brief(out, 600))
	if err != nil || !strings.Contains(out, wantVer) {
		reason := sshx.Classify(out)
		if reason == "" {
			// 归不了类时也要把原始输出的首行带出来，而不是给个笼统结论
			reason = "内核无法执行（原始输出：" + sshx.Brief(out, 160) + "）"
		}
		_, _ = sshx.Run(ctx, client, "rm -f "+stage+" "+stageGz)
		add("✗ %s —— 请重试或检查架构", reason)
		return oldVer, "", fmt.Errorf("内核校验失败，请重试或检查架构：%s", reason)
	}
	add("✓ 内核校验通过（%s）", wantVer)

	// ── 3. 备份旧内核（存在才备份） ──
	backupPath := ""
	if _, err := sshx.RunOut(ctx, client, "test -x "+binPath+" && echo yes"); err == nil {
		stamp := time.Now().Format("20060102-150405")
		backupPath = fmt.Sprintf("%s.bak-%s", binPath, stamp)
		cpCmd := priv.Wrap(fmt.Sprintf("cp -f %s %s && chmod 0755 %s", binPath, backupPath, backupPath))
		if o, err := sshx.Run(ctx, client, cpCmd); err != nil {
			add("$ %s", cpCmd)
			add("  %s", sshx.Brief(o, 400))
			add("✗ 备份旧内核失败，为避免无法回滚，已中止")
			return oldVer, "", fmt.Errorf("备份旧内核失败：%s", firstNonEmptyStr(sshx.Classify(o), sshx.Brief(o, 200)))
		}
		add("✓ 已备份旧内核 → %s", backupPath)
	} else {
		add("· 远端尚未安装 %s，本次为全新安装", name)
	}

	// ── 4. 安装：先 cp 到同目录临时名再 mv，避免 Text file busy ──
	installCmd := priv.Wrap(fmt.Sprintf(
		"cp -f %s %s.vpspanel-new && chmod 0755 %s.vpspanel-new && mv -f %s.vpspanel-new %s",
		stage, binPath, binPath, binPath, binPath))
	if o, err := sshx.Run(ctx, client, installCmd); err != nil {
		add("$ %s", installCmd)
		add("  %s", sshx.Brief(o, 600))
		reason := sshx.Classify(o)
		if reason == "" {
			reason = sshx.Brief(o, 200)
		}
		// 安装失败：回滚（此步之前现网二进制未变，通常无需回滚，但仍显式告知）
		add("→ 正在执行回滚…")
		if backupPath != "" {
			if _, e := sshx.Run(ctx, client, priv.Wrap("cp -f "+backupPath+" "+binPath)); e == nil {
				add("✓ 旧内核已恢复：%s", backupPath)
			} else {
				add("! 恢复旧内核失败，请手动执行：sudo cp -f %s %s", backupPath, binPath)
			}
		} else {
			add("· 无旧版本可恢复（首次安装）")
		}
		_, _ = sshx.Run(ctx, client, "rm -f "+stage+" "+stageGz)
		return oldVer, "", fmt.Errorf("安装 %s 失败：%s", name, reason)
	}
	add("✓ 已安装到 %s", binPath)

	// ── 5. 安装后复核（读真实版本号） ──
	nowOut, _ := sshx.RunOut(ctx, client, binPath+" version 2>/dev/null | head -1")
	newVer := parseKernelVersion(name, nowOut)
	if newVer == "" || !strings.Contains(nowOut, wantVer) {
		add("✗ 安装后版本校验失败，输出：%s", sshx.Brief(nowOut, 200))
		add("→ 正在执行回滚…")
		if backupPath != "" {
			if _, e := sshx.Run(ctx, client, priv.Wrap("cp -f "+backupPath+" "+binPath)); e == nil {
				add("✓ 旧内核已恢复：%s", backupPath)
			}
		} else {
			_, _ = sshx.Run(ctx, client, priv.Wrap("rm -f "+binPath))
			add("✓ 已移除不可用的新内核")
		}
		_, _ = sshx.Run(ctx, client, "rm -f "+stage+" "+stageGz)
		return oldVer, "", fmt.Errorf("安装后版本校验失败（期望 %s），已回滚", wantVer)
	}
	add("✓ %s v%s 校验通过", name, newVer)

	// ── 6. 清理临时文件 ──
	_, _ = sshx.Run(ctx, client, "rm -f "+stage+" "+stageGz)
	return oldVer, newVer, nil
}

func parseKernelVersion(name, out string) string {
	if name == "sing-box" {
		return parseSingboxVersion(out)
	}
	return parseXrayVersion(out)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// RestartAll 重启所有 VpsPanel 托管的 xray 服务（内核更新后调用）。
// unitRe 只接受本面板的单元命名（xray / sing-box 两套）。
var unitRe = regexp.MustCompile(`^vpspanel-(xray|singbox)-[0-9]{1,5}\.service$`)

// RestartAll 重启所有 VpsPanel 托管的节点服务（xray + sing-box 两套都要覆盖）。
func RestartAll(ctx context.Context, client *ssh.Client, logf func(string)) (int, error) {
	add := logfTo(logf)
	if _, err := sshx.RunOut(ctx, client, "test -d /run/systemd/system && echo yes"); err != nil {
		// nohup 模式：按配置目录分别重启两套内核
		o, _ := sshx.RunOut(ctx, client,
			`for f in /usr/local/etc/xray/config-*.json; do [ -f "$f" ] || continue; `+
				`pkill -f "[x]ray -config $f" 2>/dev/null; sleep 0.2; `+
				`nohup /usr/local/bin/xray -config "$f" >/var/log/vpspanel-$(basename "$f" .json).log 2>&1 & done; `+
				`for f in /usr/local/etc/sing-box/config-*.json; do [ -f "$f" ] || continue; `+
				`pkill -f "[s]ing-box run -c $f" 2>/dev/null; sleep 0.2; `+
				`nohup /usr/local/bin/sing-box run -c "$f" >/var/log/vpspanel-sb-$(basename "$f" .json).log 2>&1 & done; `+
				`sleep 0.5; ls -1 /usr/local/etc/xray/config-*.json /usr/local/etc/sing-box/config-*.json 2>/dev/null | wc -l`)
		n := 0
		fmt.Sscanf(strings.TrimSpace(o), "%d", &n)
		add("✓ 已重启 %d 个节点实例（nohup：xray + sing-box）", n)
		return n, nil
	}

	o, _ := sshx.RunOut(ctx, client, `systemctl list-units --type=service --all --no-legend 'vpspanel-*.service' 2>/dev/null | awk '{print $1}'`)
	units := strings.Fields(strings.TrimSpace(o))
	n := 0
	for _, u := range units {
		// 单元名来自远端输出，启动前白名单校验（防注入）
		if !unitRe.MatchString(u) {
			add("跳过可疑单元：%s", u)
			continue
		}
		if _, err := sshx.Run(ctx, client, "systemctl restart "+u); err != nil {
			add("! 重启 %s 失败", u)
			continue
		}
		n++
	}
	if n == 0 {
		add("· 没有已部署的节点服务需要重启")
	} else {
		add("✓ 已重启 %d 个节点服务（xray + sing-box）", n)
	}
	return n, nil
}

func logfTo(logf func(string)) func(string, ...any) {
	return func(f string, a ...any) {
		if logf != nil {
			logf(fmt.Sprintf(f, a...))
		}
	}
}

func uploadGz(client *ssh.Client, data []byte, remote string, add func(string, ...any)) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	total := len(data)
	go func() {
		defer stdin.Close()
		const chunk = 128 * 1024
		next := 25
		for i := 0; i < total; i += chunk {
			end := i + chunk
			if end > total {
				end = total
			}
			if _, err := stdin.Write(data[i:end]); err != nil {
				return
			}
			if pct := end * 100 / total; pct >= next {
				add("  推送中 %d%%", pct)
				next += 25
			}
		}
	}()
	return sess.Run("cat > " + remote)
}
