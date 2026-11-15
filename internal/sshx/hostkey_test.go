package sshx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostKeysTOFU(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts.json")
	hk := LoadHostKeys(path)

	// 第一次：未知指纹 -> 记录并放行
	if err := hk.Verify("1.2.3.4:22", "FP1"); err != nil {
		t.Fatalf("首次连接应放行: %v", err)
	}
	// 第二次：相同指纹 -> 放行
	if err := hk.Verify("1.2.3.4:22", "FP1"); err != nil {
		t.Fatalf("相同指纹应放行: %v", err)
	}
	// 指纹变化 -> 拒绝（中间人/换机）
	err := hk.Verify("1.2.3.4:22", "FP2")
	if err == nil {
		t.Fatal("指纹变化必须拒连")
	}
	// 不同主机互不影响
	if err := hk.Verify("5.6.7.8:22", "FP3"); err != nil {
		t.Fatalf("不同主机应独立记录: %v", err)
	}

	// 持久化：重新加载后仍然记得
	hk2 := LoadHostKeys(path)
	if fp, ok := hk2.Known("1.2.3.4:22"); !ok || fp != "FP1" {
		t.Fatalf("指纹未持久化: %q %v", fp, ok)
	}
	if err := hk2.Verify("1.2.3.4:22", "FP2"); err == nil {
		t.Fatal("重启后仍应拒绝指纹变化")
	}

	// 文件权限 0600
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("指纹文件不存在: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("指纹文件权限应为 0600，实际 %o", st.Mode().Perm())
	}
}

func TestHostKeysNoPath(t *testing.T) {
	hk := LoadHostKeys("")
	if err := hk.Verify("h:22", "FP"); err != nil {
		t.Fatalf("无路径时也应能在内存中工作: %v", err)
	}
	if err := hk.Verify("h:22", "FP2"); err == nil {
		t.Fatal("内存模式也必须拒绝指纹变化")
	}
}
