package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"vpspanel/internal/config"
	"vpspanel/internal/crypto"
	"vpspanel/internal/store"
)

func newTestServer(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	box, err := crypto.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("初始化密钥失败: %v", err)
	}
	cfg := &config.Config{DataDir: dir, DBPath: filepath.Join(dir, "test.db"), Port: 18080}
	return New(db, cfg, box), db
}

func do(t *testing.T, r *gin.Engine, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Host = "127.0.0.1:18080" // 通过 SecurityGuard 的 Host 校验
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// P0：主机字段的注入载荷必须在入口被拒绝
func TestServerCreateRejectsInjection(t *testing.T) {
	r, _ := newTestServer(t)
	payloads := []string{
		`{"name":"evil","host":"1.1.1.1; rm -rf /","ssh_user":"root","password":"x"}`,
		`{"name":"evil","host":"1.1.1.1 && reboot","ssh_user":"root","password":"x"}`,
		`{"name":"evil","host":"$(id)","ssh_user":"root","password":"x"}`,
		`{"name":"evil","host":"a|b","ssh_user":"root","password":"x"}`,
	}
	for _, p := range payloads {
		code, body := do(t, r, "POST", "/api/servers", p)
		if code != http.StatusBadRequest {
			t.Errorf("注入载荷应返回 400，实际 %d: %v", code, body)
		}
	}
}

// P0：家宽落地节点同样必须校验 host（这里曾被漏掉）
func TestLandingCreateRejectsInjection(t *testing.T) {
	r, _ := newTestServer(t)
	code, body := do(t, r, "POST", "/api/landing-nodes",
		`{"name":"home","host":"1.2.3.4; touch /tmp/pwned","port":1080}`)
	if code != http.StatusBadRequest {
		t.Fatalf("家宽节点注入载荷应被拒绝，实际 %d: %v", code, body)
	}
}

// 边界：端口 0 / 65536 / -1 / 非数字
func TestDeployPortBoundaries(t *testing.T) {
	r, _ := newTestServer(t)
	cases := []struct {
		body string
		want int
	}{
		{`{"server_ids":[1],"protocol":"vless","port":65536}`, 400},
		{`{"server_ids":[1],"protocol":"vless","port":-1}`, 400},
		{`{"server_ids":[1],"protocol":"vless","port":"abc"}`, 400},
		{`{"server_ids":[],"protocol":"vless","port":443}`, 400},
	}
	for _, c := range cases {
		code, body := do(t, r, "POST", "/api/deploy", c.body)
		if code != c.want {
			t.Errorf("%s 期望 %d，实际 %d: %v", c.body, c.want, code, body)
		}
	}
}

// 列表接口必须输出单行 os/specs（即使库里存了脏数据）
func TestServerListSanitizesOS(t *testing.T) {
	r, dbw := newTestServer(t)
	if err := dbw.Create(&store.Server{
		Name: "dirty", Host: "1.1.1.1", SSHPort: 22, SSHUser: "root",
		OSInfo:   "Could not chdir to home directory /home/next\nDebian GNU/Linux 12 (bookworm)",
		CPUCores: 2, MemMB: 1024, DiskGB: 20, Status: "online",
	}).Error; err != nil {
		t.Fatalf("插入测试数据失败: %v", err)
	}
	code, body := do(t, r, "GET", "/api/servers", "")
	if code != 200 {
		t.Fatalf("列表接口失败: %d", code)
	}
	items := body["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("列表为空")
	}
	row := items[0].(map[string]any)
	osField, _ := row["os"].(string)
	if strings.ContainsAny(osField, "\r\n") {
		t.Fatalf("os 字段含换行: %q", osField)
	}
	if strings.Contains(osField, "Could not chdir") {
		t.Fatalf("os 字段仍含登录告警: %q", osField)
	}
	if !strings.Contains(osField, "Debian GNU/Linux 12") {
		t.Fatalf("os 字段未提取出干净发行版名: %q", osField)
	}
}

// 切换认证方式却不给新凭证 -> 拒绝（避免密文与 auth_type 不匹配）
func TestUpdateRejectsAuthSwitchWithoutSecret(t *testing.T) {
	r, _ := newTestServer(t)
	code, _ := do(t, r, "POST", "/api/servers",
		`{"name":"n","host":"1.1.1.1","ssh_user":"root","auth_type":"password","password":"p"}`)
	if code != 200 {
		t.Fatalf("创建失败: %d", code)
	}
	code, body := do(t, r, "PUT", "/api/servers/1",
		`{"name":"n","host":"1.1.1.1","ssh_user":"root","auth_type":"key"}`)
	if code != http.StatusBadRequest {
		t.Errorf("应拒绝无凭证的认证方式切换，实际 %d: %v", code, body)
	}
}

// 凭证绝不能出现在任何 API 响应里
func TestSecretNeverReturned(t *testing.T) {
	r, _ := newTestServer(t)
	code, _ := do(t, r, "POST", "/api/servers",
		`{"name":"n","host":"1.1.1.1","ssh_user":"root","auth_type":"password","password":"SuperSecret123"}`)
	if code != 200 {
		t.Fatalf("创建失败: %d", code)
	}
	_, body := do(t, r, "GET", "/api/servers", "")
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "SuperSecret123") {
		t.Fatalf("响应泄露了密码明文")
	}
}

// P2：失败部署记录只保留最近 20 条，避免 DB 无界增长
func TestPruneFailures(t *testing.T) {
	_, db := newTestServer(t)
	s := &Server{DB: db}
	// deployments.server_id 有外键，先建一台服务器
	if err := db.Create(&store.Server{ID: 9, Name: "s9", Host: "1.1.1.1", SSHPort: 22, SSHUser: "root"}).Error; err != nil {
		t.Fatalf("创建测试服务器失败: %v", err)
	}
	for i := 0; i < 25; i++ {
		db.Create(&store.Deployment{ServerID: 9, Protocol: "vless", Port: 10000 + i, Status: "failed"})
	}
	db.Create(&store.Deployment{ServerID: 9, Protocol: "vless", Port: 443, Status: "success"})

	s.pruneFailures(9)

	var failed, total int64
	db.Model(&store.Deployment{}).Where("server_id = ? AND status = ?", 9, "failed").Count(&failed)
	db.Model(&store.Deployment{}).Where("server_id = ?", 9).Count(&total)
	if failed != 20 {
		t.Fatalf("失败记录应裁剪到 20 条，实际 %d", failed)
	}
	if total != 21 {
		t.Fatalf("成功记录不应被裁剪，实际总数 %d", total)
	}
}
