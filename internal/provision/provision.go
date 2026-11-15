// Package provision 是一键部署引擎。
//
// 设计原则（对应 architecture.md 第 5 节）：
//   - 不 curl | bash，全程自己控：上传二进制 → 渲染配置 → 本地校验 → 备份 → 切换 → 验活；
//   - 每一步失败即中止，且尽量不破坏现网；
//   - 幂等：同端口重复部署 = 覆盖配置 + 重启，不产生重复服务。
//
// 结构上分为三层，便于组合场景（链路、家宽落地）复用：
//
//	prepare()  预检：架构 → 端口 → 内核
//	install()  落地：写配置 → 校验 → 备份 → 启动 → 验活 → 防火墙
//	Deploy()   单协议：prepare + 渲染 + install + 生成链接
package provision

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"vpspanel/internal/kernel"
	"vpspanel/internal/netcheck"
	"vpspanel/internal/sshx"
)

// DefaultPort 是未指定端口时的默认值（对齐验收标准：默认 443）。
const DefaultPort = 443

// Spec 描述一次部署。
type Spec struct {
	Protocol string `json:"protocol"` // vless | vmess | shadowsocks | socks | http
	Port     int    `json:"port"`
	Tag      string `json:"tag"` // 名称，写进分享链接的备注
	Dest     string `json:"dest"`
	SNI      string `json:"sni"`

	// 以下由引擎自动生成/填充
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	User     string `json:"user"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	PrivKey  string `json:"private_key"`
	PubKey   string `json:"public_key"`
	ShortID  string `json:"short_id"`
	Network  string `json:"network"` // tcp | ws（vless 用）
}

type Result struct {
	Logs   []string          `json:"logs"`
	Config string            `json:"config"`
	Link   string            `json:"link"`
	Meta   map[string]string `json:"meta"`
}

// ── 工具函数 ───────────────────────────────────────────────────

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// NewUUID 导出给 chain / residential 复用。
func NewUUID() string { return newUUID() }

// ServiceName 统一的 systemd 单元名（按端口区分，支持同机多实例）。
func ServiceName(port int) string { return fmt.Sprintf("vpspanel-xray-%d", port) }

// certDir 统一存放自签证书（Trojan / 未来的其它 TLS 协议共用）。
func certDir() string { return "/usr/local/etc/xray/certs" }

func certPath(port int) string { return fmt.Sprintf("%s/trojan-%d.crt", certDir(), port) }
func keyPath(port int) string  { return fmt.Sprintf("%s/trojan-%d.key", certDir(), port) }

// EnsureCert 为 TLS 类协议准备自签证书（幂等：已存在则不重复生成）。
func EnsureCert(ctx context.Context, client *ssh.Client, port int, logf func(string)) error {
	add := logger(logf)
	exist, _ := sshx.RunOut(ctx, client, fmt.Sprintf("test -f %s && test -f %s && echo yes", certPath(port), keyPath(port)))
	if strings.TrimSpace(exist) == "yes" {
		add("✓ 复用已有自签证书 (:%d)", port)
		return nil
	}
	if _, err := sshx.RunOut(ctx, client, "command -v openssl"); err != nil {
		return fmt.Errorf("远端缺少 openssl，无法为 Trojan 生成自签证书（可 apt install openssl）")
	}
	cmd := fmt.Sprintf(
		"mkdir -p %s && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 "+
			"-subj '/CN=%d' -keyout %s -out %s >/dev/null 2>&1 && chmod 600 %s && echo done",
		certDir(), port, keyPath(port), certPath(port), keyPath(port))
	o, err := sshx.RunOut(ctx, client, cmd)
	if err != nil || !strings.Contains(o, "done") {
		return fmt.Errorf("生成自签证书失败: %v", err)
	}
	add("✓ 已生成自签证书 (:%d, 10 年有效)", port)
	return nil
}

// SingboxServiceName / SingboxConfigPath：sing-box 实例的命名约定（与 xray 隔离）。
func SingboxServiceName(port int) string { return fmt.Sprintf("vpspanel-singbox-%d", port) }
func SingboxConfigPath(port int) string {
	return fmt.Sprintf("/usr/local/etc/sing-box/config-%d.json", port)
}

// ConfigPath 统一的远端配置路径。
func ConfigPath(port int) string { return fmt.Sprintf("/usr/local/etc/xray/config-%d.json", port) }

// ── prepare：预检 ──────────────────────────────────────────────

// isOwnService 判断端口上的监听者是否为本面板托管的 xray 实例。
// 依据：同端口存在本面板生成的配置或 systemd 单元。用于「幂等重部署」放行。
func isOwnService(ctx context.Context, client *ssh.Client, port int) bool {
	// 同时覆盖 xray 与 sing-box 两套命名，避免 Hysteria2 无法重部署
	cmd := fmt.Sprintf(
		"for f in %s %s; do [ -f \"$f\" ] && echo yes; done; "+
			"for u in %s %s; do [ -f \"/etc/systemd/system/$u.service\" ] && echo yes; done; true",
		ConfigPath(port), SingboxConfigPath(port), ServiceName(port), SingboxServiceName(port))
	o, err := sshx.RunOut(ctx, client, cmd)
	return err == nil && strings.Contains(o, "yes")
}

// cleanArch 从可能被污染的 uname 输出中取出干净的架构字符串。
func cleanArch(raw string) string {
	for _, f := range strings.Fields(sshx.Sanitize(raw)) {
		switch {
		case strings.Contains(f, "x86_64"), strings.Contains(f, "amd64"),
			strings.Contains(f, "aarch64"), strings.Contains(f, "arm64"),
			strings.Contains(f, "armv7"), strings.Contains(f, "i686"):
			return f
		}
	}
	return sshx.Sanitize(raw)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Prepare 检查架构、端口占用，并确保内核已就绪。
func Prepare(ctx context.Context, client *ssh.Client, port int, logf func(string)) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口 %d 不合法，需在 1-65535 之间", port)
	}
	add := logger(logf)
	// 采集类命令一律 RunOut：SSH 登录告警（Could not chdir ...）写在 stderr，不能进数据
	archRaw, err := sshx.RunOut(ctx, client, "uname -m")
	if err != nil {
		return fmt.Errorf("执行 uname 失败: %w", err)
	}
	arch := cleanArch(archRaw)
	if arch == "" || (!strings.Contains(arch, "x86_64") && !strings.Contains(arch, "amd64")) {
		return fmt.Errorf("暂只支持 x86_64 架构，当前为 %s", firstNonEmpty(arch, "未知"))
	}
	add("✓ 架构检查通过 (%s)", arch)

	// 端口占用：解析监听表后精确比较端口号，不做 `grep 输出非空` 这种脆弱判断
	busy, detail, err := netcheck.InUse(ctx, client, port)
	switch {
	case err != nil:
		add("· 无法读取监听端口（%v），跳过占用检查", err)
	case busy && isOwnService(ctx, client, port):
		// 端口被本面板上一版部署占用：按「更新」处理，允许重复部署（幂等）
		add("· 端口 %d 由本面板托管，按更新处理", port)
	case busy:
		return fmt.Errorf("端口 %d 已被占用（%s），请换一个端口", port, detail)
	default:
		add("✓ 端口 %d 可用", port)
	}

	oldVer, newVer, err := kernel.EnsureXray(ctx, client, logf)
	if err != nil {
		return err
	}
	if oldVer != "" && oldVer != newVer {
		add("✓ 内核已更新: %s → %s", oldVer, newVer)
	} else {
		add("✓ 内核就绪: %s", newVer)
	}
	return nil
}

// ── install：写配置 → 校验 → 备份 → 启动 → 验活 → 防火墙 ───────

// Install 上传配置并启动服务。失败时尽量回滚到旧配置。
// svcOpts 描述一个待安装的服务，xray 与 sing-box 共用同一套安装/校验/回滚流程。
type svcOpts struct {
	Port     int
	Bin      string // /usr/local/bin/xray | /usr/local/bin/sing-box
	ExecArgs string // 传给 Bin 的参数，如 "-config /path" 或 "run -c /path"
	UnitName string
	Desc     string
	CfgPath  string
	CfgJSON  string
	CheckCmd string // 校验命令（%s 会被替换为临时配置路径）
	Proto    string // tcp | udp，用于防火墙
}

// installService 是通用安装器：写配置 → 校验 → 备份 → 原子替换 → 启动 → 验活 → 防火墙。
// 失败时尽量回滚到旧配置；校验不通过绝不覆盖现网。
func installService(ctx context.Context, client *ssh.Client, o svcOpts, logf func(string)) error {
	add := logger(logf)
	run := func(cmd string) (string, error) { return sshx.Run(ctx, client, cmd) }

	if err := o.validate(); err != nil {
		return err
	}

	// 权限预检：非 root 时后续写 /usr/local/etc 与 /etc/systemd/system 都需要 sudo
	priv := sshx.DetectPrivilege(ctx, client)
	if err := priv.Check(); err != nil {
		add("✗ 权限不足：%v", err)
		return err
	}
	wrun := func(cmd string) (string, error) { return sshx.Run(ctx, client, priv.Wrap(cmd)) }

	if out, err := wrun("mkdir -p " + filepath.Dir(o.CfgPath)); err != nil {
		add("$ %s", priv.Wrap("mkdir -p "+filepath.Dir(o.CfgPath)))
		add("  %s", sshx.Brief(out, 400))
		return fmt.Errorf("创建配置目录失败：%s", firstNonEmpty(sshx.Classify(out), sshx.Brief(out, 200)))
	}

	// 备份旧配置（存在才备份），只读 stdout 以免被登录告警污染
	backup := ""
	if out, err := sshx.RunOut(ctx, client, priv.Wrap(fmt.Sprintf(
		"test -f %s && cp -f %s %s.bak.$(date +%%s) && ls -1t %s.bak.* | head -1 || true",
		o.CfgPath, o.CfgPath, o.CfgPath, o.CfgPath))); err == nil {
		backup = sshx.Sanitize(out)
	}

	// 先写 .new 再校验，通过才原子替换（xray 依扩展名判格式，临时文件必须 .json 结尾）
	tmp := strings.TrimSuffix(o.CfgPath, ".json") + ".new.json"
	if err := writeFilePriv(client, priv, tmp, []byte(o.CfgJSON), "0600"); err != nil {
		add("✗ 写入配置失败：%v", err)
		return fmt.Errorf("写入配置失败（%s）: %w", firstNonEmpty(sshx.Classify(err.Error()), "可能是权限问题"), err)
	}
	if out, err := run(fmt.Sprintf(o.CheckCmd, tmp)); err != nil {
		_, _ = wrun("rm -f " + tmp)
		add("$ %s", fmt.Sprintf(o.CheckCmd, tmp))
		add("  %s", sshx.Brief(out, 600))
		return fmt.Errorf("配置校验失败，已中止（现网未改动）: %s", sshx.Brief(out, 300))
	}
	if out, err := wrun(fmt.Sprintf("mv -f %s %s", tmp, o.CfgPath)); err != nil {
		add("  %s", sshx.Brief(out, 400))
		return fmt.Errorf("替换配置失败：%s", firstNonEmpty(sshx.Classify(out), sshx.Brief(out, 200)))
	}
	add("✓ 配置校验通过")

	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s %s
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, o.Desc, o.Bin, o.ExecArgs)

	hasSystemd := false
	if _, err := sshx.RunOut(ctx, client, "test -d /run/systemd/system && echo yes"); err == nil {
		hasSystemd = true
	}
	rollbackConfig := func() {
		if backup != "" {
			add("→ 正在执行回滚…")
			if _, err := wrun(fmt.Sprintf("cp -f %s %s", backup, o.CfgPath)); err == nil {
				add("✓ 旧配置已恢复：%s", backup)
			} else {
				add("! 恢复旧配置失败，请手动执行：%s", priv.Wrap("cp -f "+backup+" "+o.CfgPath))
			}
		}
	}

	if hasSystemd {
		if err := writeFilePriv(client, priv, "/etc/systemd/system/"+o.UnitName+".service", []byte(unit), "0644"); err != nil {
			return fmt.Errorf("写入 systemd 单元失败（%s）: %w", firstNonEmpty(sshx.Classify(err.Error()), "权限问题"), err)
		}
		_, _ = wrun("systemctl daemon-reload")
		if out, err := wrun(fmt.Sprintf("systemctl enable %s.service >/dev/null 2>&1; systemctl restart %s.service", o.UnitName, o.UnitName)); err != nil {
			st, _ := wrun(fmt.Sprintf("systemctl status %s.service --no-pager -l | tail -20", o.UnitName))
			add("  %s", sshx.Brief(out, 500))
			add("→ 正在执行回滚…")
			rollbackConfig()
			return fmt.Errorf("服务启动失败: %v\n%s", err, sshx.Brief(st, 800))
		}
		add("✓ systemd 服务已启动: %s.service", o.UnitName)
	} else {
		_, _ = wrun(fmt.Sprintf("pkill -f '%s %s' || true", o.Bin, o.ExecArgs))
		time.Sleep(300 * time.Millisecond)
		if _, err := wrun(fmt.Sprintf("nohup %s %s >/var/log/%s.log 2>&1 &", o.Bin, o.ExecArgs, o.UnitName)); err != nil {
			rollbackConfig()
			return fmt.Errorf("启动失败: %w", err)
		}
		add("✓ 无 systemd，已用 nohup 启动（日志 /var/log/%s.log）", o.UnitName)
	}

	// 验活：轮询监听表（Go 侧精确解析，不受 stderr 污染）
	ok := false
	for i := 0; i < 10; i++ {
		time.Sleep(700 * time.Millisecond)
		if busy, _, e := netcheck.InUse(ctx, client, o.Port); e == nil && busy {
			ok = true
			break
		}
	}
	if !ok {
		logs, _ := run(fmt.Sprintf("tail -20 /var/log/%s.log 2>/dev/null; journalctl -u %s.service --no-pager -n 20 2>/dev/null", o.UnitName, o.UnitName))
		return fmt.Errorf("服务未监听端口 %d\n%s", o.Port, strings.TrimSpace(logs))
	}
	add("✓ 端口 %d 正在监听", o.Port)

	OpenFirewall(ctx, client, o.Port, o.Proto, logf)
	return nil
}

func (o svcOpts) validate() error {
	if o.Bin == "" || o.CfgPath == "" || o.UnitName == "" || o.CheckCmd == "" {
		return fmt.Errorf("内部错误：服务描述不完整")
	}
	return nil
}

// Install 安装 xray 服务（保持既有签名，供测试与单协议部署使用）。
func Install(ctx context.Context, client *ssh.Client, port int, cfgJSON string, logf func(string)) error {
	return installService(ctx, client, svcOpts{
		Port:     port,
		Bin:      "/usr/local/bin/xray",
		ExecArgs: "-config " + ConfigPath(port),
		UnitName: ServiceName(port),
		Desc:     fmt.Sprintf("VpsPanel xray (:%d)", port),
		CfgPath:  ConfigPath(port),
		CfgJSON:  cfgJSON,
		CheckCmd: "/usr/local/bin/xray -test -config %s 2>&1",
		Proto:    "tcp",
	}, logf)
}

// InstallSingbox 安装 sing-box 服务（Hysteria2 等协议使用）。
func InstallSingbox(ctx context.Context, client *ssh.Client, port int, cfgJSON string, logf func(string)) error {
	return installService(ctx, client, svcOpts{
		Port:     port,
		Bin:      "/usr/local/bin/sing-box",
		ExecArgs: "run -c " + SingboxConfigPath(port),
		UnitName: SingboxServiceName(port),
		Desc:     fmt.Sprintf("VpsPanel sing-box (:%d)", port),
		CfgPath:  SingboxConfigPath(port),
		CfgJSON:  cfgJSON,
		CheckCmd: "/usr/local/bin/sing-box check -c %s 2>&1",
		Proto:    "udp",
	}, logf)
}

// ── Deploy：单协议部署 ────────────────────────────────────────

func Deploy(ctx context.Context, client *ssh.Client, host string, spec *Spec, logf func(string)) (*Result, error) {
	res := &Result{Meta: map[string]string{}}
	add := logger(logf)

	if spec.Port == 0 {
		spec.Port = DefaultPort
	}
	if err := Prepare(ctx, client, spec.Port, logf); err != nil {
		return nil, err
	}

	// 生成参数
	if spec.Tag == "" {
		spec.Tag = fmt.Sprintf("%s-%d", spec.Protocol, spec.Port)
	}
	if spec.UUID == "" {
		spec.UUID = newUUID()
	}
	if spec.Path == "" {
		spec.Path = "/" + randHex(4)
	}
	if spec.Network == "" {
		spec.Network = "tcp"
	}

	switch spec.Protocol {
	case "vless":
		if spec.Network == "tcp" {
			if spec.Dest == "" {
				spec.Dest = "www.microsoft.com:443"
			}
			if spec.SNI == "" {
				spec.SNI = strings.Split(spec.Dest, ":")[0]
			}
			if spec.ShortID == "" {
				spec.ShortID = randHex(4)
			}
			o, err := sshx.RunOut(ctx, client, "/usr/local/bin/xray x25519 2>/dev/null")
			if err == nil {
				spec.PrivKey = PickField(o, "(?i)private\\s*key")
				spec.PubKey = PickField(o, "(?i)(?:public\\s*key|password)(?:\\s*\\([^)]*\\))?")
			}
			if spec.PrivKey == "" || spec.PubKey == "" {
				return nil, fmt.Errorf("生成 Reality 密钥失败: %s", o)
			}
			add("✓ Reality 密钥已生成 (shortId=%s, sni=%s)", spec.ShortID, spec.SNI)
		}
	case "vmess":
		spec.Path = "/" + randHex(4)
	case "shadowsocks":
		if spec.Method == "" {
			spec.Method = "aes-256-gcm"
		}
		if spec.Password == "" {
			spec.Password = randB64(12)
		}
	case "trojan", "hysteria2":
		if spec.Password == "" {
			spec.Password = randB64(12)
		}
	case "socks", "http":
		if spec.User == "" {
			spec.User = "vp" + randHex(2)
		}
		if spec.Password == "" {
			spec.Password = randB64(9)
		}
	}

	if spec.Protocol == "trojan" || spec.Protocol == "hysteria2" {
		if err := EnsureCert(ctx, client, spec.Port, logf); err != nil {
			return nil, err
		}
	}

	// WireGuard 走系统内核，单独一条路径
	if spec.Protocol == "wireguard" {
		wg, err := DeployWireGuard(ctx, client, host, spec, logf)
		if err != nil {
			return nil, err
		}
		return wg, nil
	}

	// Hysteria2 走 sing-box 内核（xray 没有该协议）
	if spec.Protocol == "hysteria2" {
		oldV, newV, err := kernel.EnsureSingbox(ctx, client, logf)
		if err != nil {
			return nil, err
		}
		if oldV != "" && oldV != newV {
			add("✓ sing-box 已更新: %s → %s", oldV, newV)
		}
		cfgSB, err := renderHysteria2Config(spec)
		if err != nil {
			return nil, err
		}
		if err := InstallSingbox(ctx, client, spec.Port, cfgSB, logf); err != nil {
			return nil, err
		}
		res.Config = cfgSB
		res.Link = buildLink(host, spec)
		res.Meta["service"] = SingboxServiceName(spec.Port)
		res.Meta["config_path"] = SingboxConfigPath(spec.Port)
		return res, nil
	}

	cfg, err := renderConfig(spec)
	if err != nil {
		return nil, err
	}
	if err := Install(ctx, client, spec.Port, cfg, logf); err != nil {
		return nil, err
	}

	res.Config = cfg
	res.Link = buildLink(host, spec)
	res.Meta["service"] = ServiceName(spec.Port)
	res.Meta["config_path"] = ConfigPath(spec.Port)
	res.Meta["uuid"] = spec.UUID
	res.Meta["public_key"] = spec.PubKey
	res.Meta["short_id"] = spec.ShortID
	res.Meta["sni"] = spec.SNI
	res.Meta["dest"] = spec.Dest
	return res, nil
}

// Uninstall 停止并移除一个部署。
func Uninstall(ctx context.Context, client *ssh.Client, protocol string, port int, logf func(string)) error {
	add := logger(logf)
	if protocol == "wireguard" {
		return UninstallWireGuard(ctx, client, port, logf)
	}

	// 一个端口可能属于 xray 或 sing-box 两套命名空间（Hysteria2 走 sing-box），
	// 必须两套都清理，否则会残留 unit 与配置。
	svcs := []string{ServiceName(port), SingboxServiceName(port)}
	paths := []string{ConfigPath(port), SingboxConfigPath(port)}

	priv := sshx.DetectPrivilege(ctx, client)
	hasSystemd := false
	if _, err := sshx.Run(ctx, client, "test -d /run/systemd/system"); err == nil {
		hasSystemd = true
	}
	if hasSystemd {
		for _, svc := range svcs {
			_, _ = sshx.Run(ctx, client, priv.Wrap(fmt.Sprintf("systemctl disable --now %s.service 2>/dev/null || true", svc)))
			_, _ = sshx.Run(ctx, client, priv.Wrap(fmt.Sprintf("rm -f /etc/systemd/system/%s.service", svc)))
		}
		_, _ = sshx.Run(ctx, client, priv.Wrap("systemctl daemon-reload"))
	} else {
		add("· 未检测到 systemd，直接结束进程")
	}

	// 兜底：单元丢失 / 崩溃循环 / 非 systemd 环境，只靠 systemctl 不足以释放端口。
	// [x]ray 的括号技巧避免 pkill 匹配到本条命令自身的 shell。
	_, _ = sshx.Run(ctx, client, fmt.Sprintf(
		`pkill -f "[x]ray -config %s" 2>/dev/null; `+
			`pkill -f "[s]ing-box run -c %s" 2>/dev/null; sleep 0.2; true`,
		paths[0], paths[1]))
	add("✓ 已按配置路径兜底结束残留进程")

	for _, path := range paths {
		_, _ = sshx.Run(ctx, client, priv.Wrap(fmt.Sprintf("rm -f %s %s.bak.* %s.new.json",
			path, path, strings.TrimSuffix(path, ".json"))))
	}
	add("✓ 已停止并移除 %s (%d)", protocol, port)
	return nil
}

// ── 内部工具 ───────────────────────────────────────────────────

func logger(logf func(string)) func(string, ...any) {
	return func(format string, a ...any) {
		if logf != nil {
			logf(fmt.Sprintf(format, a...))
		}
	}
}

// PickField 从 xray 输出里取 "Key: value" 形式的字段（兼容 PrivateKey:/Public key:/Password (PublicKey): 等写法）。
func PickField(text, pattern string) string {
	re := regexp.MustCompile(pattern + `\s*[:：]\s*(\S+)`)
	m := re.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// writeFilePriv 写入文件；非 root 时通过 sudo -n 提权（用于 /usr/local/etc、/etc/systemd/system）。
func writeFilePriv(client *ssh.Client, priv sshx.Privilege, path string, data []byte, mode string) error {
	if priv.NeedSudo() {
		return writeFileCmd(client, fmt.Sprintf("sudo -n sh -c 'cat > %s && chmod %s %s'", path, mode, path), data)
	}
	return writeFile(client, path, data, mode)
}

func writeFileCmd(client *ssh.Client, cmd string, data []byte) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		_, _ = stdin.Write(data)
		_ = stdin.Close()
	}()
	return sess.Run(cmd)
}

func writeFile(client *ssh.Client, path string, data []byte, mode string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		_, _ = stdin.Write(data)
		_ = stdin.Close()
	}()
	return sess.Run(fmt.Sprintf("cat > %s && chmod %s %s", path, mode, path))
}

// FirewallKind 是远端启用的防火墙类型。
type FirewallKind string

const (
	FWNone      FirewallKind = "none"
	FWUfw       FirewallKind = "ufw"
	FWFirewalld FirewallKind = "firewalld"
)

// looksLikePath 判断命令输出是否真的是一个可执行文件路径。
// SSH 登录告警（"Could not chdir ..."）之类的噪声不含 "/"，因此不会被误判为「已安装」。
func looksLikePath(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "/") && !strings.ContainsAny(s, "\n\r")
}

// activeRe 用词边界匹配，避免 "inactive" / "not running" 被误判为启用。
var activeRe = regexp.MustCompile(`(?i)\bactive\b`)

// decideFirewall 是纯函数，便于单元测试：输入四段原始输出，输出判定结果。
func decideFirewall(ufwPath, ufwStatus, fwPath, fwState string) FirewallKind {
	if looksLikePath(ufwPath) && activeRe.MatchString(ufwStatus) {
		return FWUfw
	}
	// firewalld --state 的正常输出就是 "running"，其余（not running / failed）一律不算
	if looksLikePath(fwPath) && strings.EqualFold(strings.TrimSpace(fwState), "running") {
		return FWFirewalld
	}
	return FWNone
}

// OpenFirewall 尝试为端口放行 ufw / firewalld，并提示云安全组。
func OpenFirewall(ctx context.Context, client *ssh.Client, port int, proto string, logf func(string)) {
	add := logger(logf)
	// 全部走 RunOut：探测类输出不允许被 stderr 污染
	ufwPath, _ := sshx.RunOut(ctx, client, "command -v ufw 2>/dev/null")
	ufwStatus, _ := sshx.RunOut(ctx, client, "ufw status 2>/dev/null | head -1")
	fwPath, _ := sshx.RunOut(ctx, client, "command -v firewall-cmd 2>/dev/null")
	fwState, _ := sshx.RunOut(ctx, client, "firewall-cmd --state 2>/dev/null")

	switch decideFirewall(ufwPath, ufwStatus, fwPath, fwState) {
	case FWUfw:
		if _, err := sshx.Run(ctx, client, fmt.Sprintf("ufw allow %d/tcp >/dev/null 2>&1", port)); err != nil {
			add("! ufw 放行 %d/tcp 失败（服务已启动，请手动 ufw allow %d）", port, port)
		} else {
			add("✓ ufw 已放行 %d/tcp", port)
		}
		if strings.Contains(proto, "udp") {
			if _, err := sshx.Run(ctx, client, fmt.Sprintf("ufw allow %d/udp >/dev/null 2>&1", port)); err != nil {
				add("! ufw 放行 %d/udp 失败", port)
			}
		}
		add("· 别忘了：云服务商安全组也要放行 %d", port)
	case FWFirewalld:
		if _, err := sshx.Run(ctx, client, fmt.Sprintf("firewall-cmd --permanent --add-port=%d/tcp >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1", port)); err != nil {
			add("! firewalld 放行 %d/tcp 失败（服务已启动，请手动添加规则）", port)
		} else {
			add("✓ firewalld 已放行 %d/tcp", port)
		}
		add("· 别忘了：云服务商安全组也要放行 %d", port)
	default:
		add("· 未检测到启用的防火墙（ufw/firewalld），请自行确认云安全组已放行 %d", port)
	}
}

func renderConfig(spec *Spec) (string, error) {
	inbound := map[string]any{
		"listen": "0.0.0.0",
		"port":   spec.Port,
	}
	switch spec.Protocol {
	case "vless":
		inbound["protocol"] = "vless"
		client := map[string]any{"id": spec.UUID}
		stream := map[string]any{}
		if spec.Network == "ws" {
			client["flow"] = ""
			stream = map[string]any{"network": "ws", "wsSettings": map[string]any{"path": spec.Path}}
		} else {
			client["flow"] = "xtls-rprx-vision"
			stream = map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        false,
					"dest":        spec.Dest,
					"xver":        0,
					"serverNames": []string{spec.SNI},
					"privateKey":  spec.PrivKey,
					"shortIds":    []string{spec.ShortID},
				},
			}
		}
		inbound["settings"] = map[string]any{"clients": []any{client}, "decryption": "none"}
		inbound["streamSettings"] = stream
	case "vmess":
		inbound["protocol"] = "vmess"
		inbound["settings"] = map[string]any{"clients": []any{map[string]any{"id": spec.UUID, "alterId": 0}}}
		inbound["streamSettings"] = map[string]any{"network": "ws", "wsSettings": map[string]any{"path": spec.Path}}
	case "trojan":
		inbound["protocol"] = "trojan"
		inbound["settings"] = map[string]any{
			"clients": []any{map[string]any{"password": spec.Password}},
		}
		inbound["streamSettings"] = map[string]any{
			"network":  "tcp",
			"security": "tls",
			"tlsSettings": map[string]any{
				"certificates": []any{map[string]any{
					"certificateFile": certPath(spec.Port),
					"keyFile":         keyPath(spec.Port),
				}},
			},
		}
	case "shadowsocks":
		inbound["protocol"] = "shadowsocks"
		inbound["settings"] = map[string]any{"method": spec.Method, "password": spec.Password, "network": "tcp,udp"}
	case "socks":
		inbound["protocol"] = "socks"
		inbound["settings"] = map[string]any{
			"auth": "password", "udp": true,
			"accounts": []any{map[string]any{"user": spec.User, "pass": spec.Password}},
		}
	case "http":
		inbound["protocol"] = "http"
		inbound["settings"] = map[string]any{
			"accounts": []any{map[string]any{"user": spec.User, "pass": spec.Password}},
		}
	default:
		return "", fmt.Errorf("暂不支持的协议: %s", spec.Protocol)
	}
	inbound["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// renderHysteria2Config 生成 sing-box 的 Hysteria2 入站配置。
func renderHysteria2Config(spec *Spec) (string, error) {
	if spec.Password == "" {
		spec.Password = randB64(12)
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type":        "hysteria2",
			"listen":      "::",
			"listen_port": spec.Port,
			"users":       []any{map[string]any{"password": spec.Password}},
			"tls": map[string]any{
				"enabled":          true,
				"certificate_path": certPath(spec.Port),
				"key_path":         keyPath(spec.Port),
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func buildLink(host string, s *Spec) string {
	tag := url.QueryEscape(s.Tag)
	switch s.Protocol {
	case "vless":
		q := url.Values{}
		q.Set("encryption", "none")
		q.Set("type", s.Network)
		if s.Network == "ws" {
			q.Set("security", "none")
			q.Set("path", s.Path)
			q.Set("host", host)
		} else {
			q.Set("security", "reality")
			q.Set("sni", s.SNI)
			q.Set("fp", "chrome")
			q.Set("pbk", s.PubKey)
			q.Set("sid", s.ShortID)
			q.Set("flow", "xtls-rprx-vision")
		}
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", s.UUID, host, s.Port, q.Encode(), tag)
	case "vmess":
		obj := map[string]any{
			"v": "2", "ps": s.Tag, "add": host, "port": s.Port,
			"id": s.UUID, "aid": "0", "scy": "auto", "net": "ws",
			"type": "none", "host": host, "path": s.Path, "tls": "",
		}
		b, _ := json.Marshal(obj)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "hysteria2":
		// 用 url.User 而不是 QueryEscape：userinfo 里空格必须编成 %20，'+' 会被当成字面加号
		u := &url.URL{Scheme: "hysteria2", User: url.User(s.Password),
			Host: net.JoinHostPort(host, strconv.Itoa(s.Port)), Fragment: s.Tag}
		q := url.Values{}
		q.Set("sni", host)
		q.Set("insecure", "1")
		u.RawQuery = q.Encode()
		return u.String()
	case "trojan":
		u := &url.URL{Scheme: "trojan", User: url.User(s.Password),
			Host: net.JoinHostPort(host, strconv.Itoa(s.Port)), Fragment: s.Tag}
		q := url.Values{}
		q.Set("security", "tls")
		q.Set("sni", host)
		q.Set("allowInsecure", "1")
		q.Set("type", "tcp")
		u.RawQuery = q.Encode()
		return u.String()
	case "shadowsocks":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(s.Method + ":" + s.Password))
		return fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, host, s.Port, tag)
	case "socks":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(s.User + ":" + s.Password))
		return fmt.Sprintf("socks://%s@%s:%d#%s", userinfo, host, s.Port, tag)
	case "http":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(s.User + ":" + s.Password))
		return fmt.Sprintf("http://%s@%s:%d#%s", userinfo, host, s.Port, tag)
	}
	return ""
}
