package provision

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpspanel/internal/sshx"
)

// 端到端回归：在「有登录告警（Could not chdir ...）」的机器上执行 Prepare，
// 断言日志里只有干净的架构名，且不出现告警文本。
//
//	VPSPANEL_TEST_SSH=1 VPSPANEL_TEST_HOST=127.0.0.1 VPSPANEL_TEST_PORT=2224 \
//	VPSPANEL_TEST_USER=root VPSPANEL_TEST_PASS=xxxx go test ./internal/provision/ -run TestPrepare -v
func TestPrepareLogsAreCleanOnPollutedHost(t *testing.T) {
	if os.Getenv("VPSPANEL_TEST_SSH") != "1" {
		t.Skip("未设置 VPSPANEL_TEST_SSH=1，跳过集成测试")
	}
	port, _ := strconv.Atoi(os.Getenv("VPSPANEL_TEST_PORT"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := sshx.Dial(ctx, os.Getenv("VPSPANEL_TEST_HOST"), sshx.Credentials{
		User: os.Getenv("VPSPANEL_TEST_USER"), Port: port,
		Password: os.Getenv("VPSPANEL_TEST_PASS"), Timeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH 连接失败: %v", err)
	}
	defer client.Close()

	var logs []string
	// 用一个几乎不可能被占用的高位端口，避免与已有服务冲突
	if err := Prepare(ctx, client, 45678, func(m string) { logs = append(logs, m) }); err != nil {
		t.Fatalf("Prepare 失败: %v\nlogs:\n%s", err, strings.Join(logs, "\n"))
	}

	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "✓ 架构检查通过 (x86_64)") {
		t.Errorf("架构检查日志不干净，期望 '✓ 架构检查通过 (x86_64)'，实际:\n%s", joined)
	}
	for _, noise := range []string{"Could not chdir", "No such file or directory", "\r"} {
		if strings.Contains(joined, noise) {
			t.Errorf("日志中混入了噪声 %q:\n%s", noise, joined)
		}
	}
	if !strings.Contains(joined, "✓ 端口 45678 可用") {
		t.Errorf("端口检查日志缺失或被误判:\n%s", joined)
	}
}
