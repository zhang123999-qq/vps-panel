package sshx

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// 集成测试：验证「stderr 噪声不会污染 stdout」。
// 默认跳过；本地/CI 起一台 sshd 后可这样跑：
//
//	VPSPANEL_TEST_SSH=1 VPSPANEL_TEST_HOST=127.0.0.1 VPSPANEL_TEST_PORT=2222 \
//	VPSPANEL_TEST_USER=root VPSPANEL_TEST_PASS=xxxx go test ./internal/sshx/ -run TestRunOut -v
func TestRunOutStripsStderr(t *testing.T) {
	if os.Getenv("VPSPANEL_TEST_SSH") != "1" {
		t.Skip("未设置 VPSPANEL_TEST_SSH=1，跳过集成测试")
	}
	port, _ := strconv.Atoi(os.Getenv("VPSPANEL_TEST_PORT"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := Dial(ctx, os.Getenv("VPSPANEL_TEST_HOST"), Credentials{
		User: os.Getenv("VPSPANEL_TEST_USER"), Port: port,
		Password: os.Getenv("VPSPANEL_TEST_PASS"), Timeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH 连接失败: %v", err)
	}
	defer client.Close()

	// 远端同时往 stderr 写登录告警、往 stdout 写真实数据
	cmd := `sh -c 'echo "Could not chdir to home directory /home/next: No such file or directory" >&2; echo x86_64'`

	quiet, err := RunOut(ctx, client, cmd)
	if err != nil {
		t.Fatalf("RunOut 失败: %v", err)
	}
	if got := Sanitize(quiet); got != "x86_64" {
		t.Fatalf("RunOut 应只返回 stdout，实际 %q", quiet)
	}

	merged, err := Run(ctx, client, cmd)
	if err != nil {
		t.Fatalf("Run 失败: %v", err)
	}
	if merged == "x86_64" {
		t.Logf("注意：当前实现下 Run 也未合并 stderr（%q），不影响结论", merged)
	}
}
