package provision

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpspanel/internal/netcheck"
	"vpspanel/internal/sshx"
)

// 集成测试：失败回滚 + 幂等性。
//
//	VPSPANEL_TEST_SSH=1 VPSPANEL_TEST_HOST=127.0.0.1 VPSPANEL_TEST_PORT=2222 \
//	VPSPANEL_TEST_USER=root VPSPANEL_TEST_PASS=xxxx \
//	go test ./internal/provision/ -run TestInstall -v
func dialTest(t *testing.T) (*sshx.Credentials, string, int) {
	t.Helper()
	if os.Getenv("VPSPANEL_TEST_SSH") != "1" {
		t.Skip("未设置 VPSPANEL_TEST_SSH=1，跳过集成测试")
	}
	port, _ := strconv.Atoi(os.Getenv("VPSPANEL_TEST_PORT"))
	c := &sshx.Credentials{
		User: os.Getenv("VPSPANEL_TEST_USER"), Port: port,
		Password: os.Getenv("VPSPANEL_TEST_PASS"), Timeout: 8 * time.Second,
	}
	return c, os.Getenv("VPSPANEL_TEST_HOST"), port
}

const validSocksConfig = `{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": %d,
    "protocol": "socks",
    "settings": {"auth": "password", "accounts": [{"user": "t", "pass": "t"}]}
  }],
  "outbounds": [{"protocol": "freedom"}]
}`

// TestInstallRollbackOnBadConfig：坏配置必须在替换前被拦下，现网配置零改动。
func TestInstallRollbackOnBadConfig(t *testing.T) {
	cred, host, _ := dialTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	client, err := sshx.Dial(ctx, host, *cred)
	if err != nil {
		t.Fatalf("SSH 连接失败: %v", err)
	}
	defer client.Close()

	const port = 45801
	good := strings.Replace(validSocksConfig, "%d", strconv.Itoa(port), 1)

	// 1) 先生成一份"现网配置"
	if err := Prepare(ctx, client, port, nil); err != nil {
		t.Fatalf("Prepare 失败: %v", err)
	}
	if err := Install(ctx, client, port, good, nil); err != nil {
		t.Fatalf("首次部署失败: %v", err)
	}
	before, err := sshx.RunOut(ctx, client, "cat "+ConfigPath(port))
	if err != nil {
		t.Fatalf("读取现网配置失败: %v", err)
	}

	// 2) 递一份坏配置：必须在 xray -test 阶段被拦下
	bad := `{"inbounds":[{"protocol":"this-does-not-exist"}]}`
	err = Install(ctx, client, port, bad, nil)
	if err == nil {
		t.Fatal("坏配置本应被拒绝")
	}
	if !strings.Contains(err.Error(), "配置校验失败") {
		t.Fatalf("错误信息应指明校验失败，实际: %v", err)
	}

	// 3) 现网配置必须与部署前完全一致，且服务仍在监听
	after, _ := sshx.RunOut(ctx, client, "cat "+ConfigPath(port))
	if strings.TrimSpace(before) != strings.TrimSpace(after) {
		t.Fatalf("坏配置污染了现网配置！\nbefore:\n%s\nafter:\n%s", before, after)
	}
	busy, _, e := netcheck.InUse(ctx, client, port)
	if e != nil || !busy {
		t.Fatalf("服务应仍在监听 %d（err=%v）", port, e)
	}
	t.Logf("✓ 坏配置被拦下，现网配置未变，服务仍在运行")
}

// TestInstallIdempotent：同配置重复部署不产生重复配置文件，服务保持可用。
func TestInstallIdempotent(t *testing.T) {
	cred, host, _ := dialTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	client, err := sshx.Dial(ctx, host, *cred)
	if err != nil {
		t.Fatalf("SSH 连接失败: %v", err)
	}
	defer client.Close()

	const port = 45802
	cfg := strings.Replace(validSocksConfig, "%d", strconv.Itoa(port), 1)

	if err := Prepare(ctx, client, port, nil); err != nil {
		t.Fatalf("Prepare 失败: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := Install(ctx, client, port, cfg, nil); err != nil {
			t.Fatalf("第 %d 次部署失败: %v", i+1, err)
		}
	}

	// 配置目录里这个端口只应有一个正式配置文件
	out, _ := sshx.RunOut(ctx, client, "ls -1 /usr/local/etc/xray/config-"+strconv.Itoa(port)+"*.json | grep -v '.bak.' | wc -l")
	if strings.TrimSpace(out) != "1" {
		t.Fatalf("应只有 1 个配置文件，实际 %s", strings.TrimSpace(out))
	}
	busy, _, _ := netcheck.InUse(ctx, client, port)
	if !busy {
		t.Fatal("重复部署后服务应仍在监听")
	}
	t.Logf("✓ 重复部署幂等：1 个配置文件，服务可用")
}
