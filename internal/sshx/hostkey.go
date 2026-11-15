// 主机密钥指纹固定（TOFU：Trust On First Use）。
//
// 现状问题：ssh.ClientConfig 若用 ssh.InsecureIgnoreHostKey()，攻击者在链路中间
// 即可冒充目标 VPS，拿到面板下发的 SSH 密码/私钥。
//
// 策略：第一次连接时记录 host:port 的公钥指纹到 data/known_hosts.json（0600），
// 之后同一 host:port 指纹变化直接拒连，并提示用户核实（重装系统/换机属正常变更，
// 需要用户手动删除该条目）。
package sshx

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
)

type HostKeys struct {
	path string
	mu   sync.Mutex
	m    map[string]string
}

// LoadHostKeys 载入（或初始化）指纹库。
func LoadHostKeys(path string) *HostKeys {
	h := &HostKeys{path: path, m: map[string]string{}}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &h.m)
	}
	return h
}

// Fingerprint 返回 SHA256 指纹（与 OpenSSH 的 SHA256:xxx 一致，去掉前缀）。
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

// Verify 校验指纹：已知则严格比对；未知则记录（TOFU）并放行。
func (h *HostKeys) Verify(hostport, fp string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if known, ok := h.m[hostport]; ok {
		if known != fp {
			return fmt.Errorf("主机密钥指纹变化（%s）：期望 %s…，实际 %s…；如确认是重装/换机，请删除 data/known_hosts.json 中该条目",
				hostport, short(known), short(fp))
		}
		return nil
	}
	h.m[hostport] = fp
	h.saveLocked()
	return nil
}

// Known 返回已记录的指纹（调试/UI 用）。
func (h *HostKeys) Known(hostport string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fp, ok := h.m[hostport]
	return fp, ok
}

// Callback 生成 ssh.HostKeyCallback。
func (h *HostKeys) Callback(hostport string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		return h.Verify(hostport, Fingerprint(key))
	}
}

func (h *HostKeys) saveLocked() {
	if h.path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(h.path), 0o700)
	raw, err := json.MarshalIndent(h.m, "", "  ")
	if err != nil {
		return
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, h.path)
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
