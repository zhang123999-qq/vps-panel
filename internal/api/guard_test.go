package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIsLocalHost(t *testing.T) {
	ok := []string{"127.0.0.1", "127.0.0.2", "localhost", "LOCALHOST", "::1", "[::1]"}
	bad := []string{"", "evil.com", "192.168.1.10", "0.0.0.0", "10.0.0.1", "127.0.0.1.evil.com"}
	for _, h := range ok {
		if !IsLocalHost(h) {
			t.Errorf("应识别为本机: %q", h)
		}
	}
	for _, h := range bad {
		if IsLocalHost(h) {
			t.Errorf("不应识别为本机: %q", h)
		}
	}
}

func TestOriginAllowed(t *testing.T) {
	if !OriginAllowed("http://127.0.0.1:18080", "127.0.0.1:18080") {
		t.Error("同源应放行")
	}
	if OriginAllowed("http://evil.com", "127.0.0.1:18080") {
		t.Error("跨站必须拒绝")
	}
	if OriginAllowed("file://x", "127.0.0.1:18080") {
		t.Error("非 http(s) 必须拒绝")
	}
}

func newGuardRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(SecurityGuard())
	h := func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) }
	// 真实处理器会读 body（ShouldBindJSON），这里模拟读取以触发 MaxBytesReader
	hPost := func(c *gin.Context) {
		if _, err := io.Copy(io.Discard, c.Request.Body); err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	}
	r.GET("/api/x", h)
	r.POST("/api/x", hPost)
	r.DELETE("/api/x", h)
	return r
}

func guardDo(r *gin.Engine, method, host, ct, origin, body string) int {
	req := httptest.NewRequest(method, "/api/x", strings.NewReader(body))
	req.Host = host
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// DNS rebinding：Host 不是本机 -> 403
func TestGuardRejectsForeignHost(t *testing.T) {
	r := newGuardRouter()
	if code := guardDo(r, "GET", "evil.example.com", "", "", ""); code != 403 {
		t.Errorf("外部 Host 应 403，实际 %d", code)
	}
	if code := guardDo(r, "GET", "127.0.0.1:18080", "", "", ""); code != 200 {
		t.Errorf("本机 Host 应 200，实际 %d", code)
	}
}

// CSRF：text/plain 的"简单请求"必须被拒
func TestGuardRejectsNonJSONWrite(t *testing.T) {
	r := newGuardRouter()
	if code := guardDo(r, "POST", "127.0.0.1:18080", "text/plain", "", `{"a":1}`); code != 415 {
		t.Errorf("text/plain 写操作应 415，实际 %d", code)
	}
	if code := guardDo(r, "POST", "127.0.0.1:18080", "application/x-www-form-urlencoded", "", "a=1"); code != 415 {
		t.Errorf("表单写操作应 415，实际 %d", code)
	}
	if code := guardDo(r, "POST", "127.0.0.1:18080", "application/json", "", `{}`); code != 200 {
		t.Errorf("JSON 写操作应放行，实际 %d", code)
	}
}

// CSRF：跨站 Origin 必须被拒
func TestGuardRejectsCrossOrigin(t *testing.T) {
	r := newGuardRouter()
	if code := guardDo(r, "POST", "127.0.0.1:18080", "application/json", "http://evil.com", `{}`); code != 403 {
		t.Errorf("跨站 Origin 应 403，实际 %d", code)
	}
	if code := guardDo(r, "POST", "127.0.0.1:18080", "application/json", "http://127.0.0.1:18080", `{}`); code != 200 {
		t.Errorf("同源 Origin 应放行，实际 %d", code)
	}
	if code := guardDo(r, "DELETE", "127.0.0.1:18080", "application/json", "", ""); code != 200 {
		t.Errorf("DELETE（无 Origin）应放行，实际 %d", code)
	}
}

// 回归：SOCKS5/HTTP 节点的账号密码不得出现在远端命令行（ps 可见）
func TestCurlProxyConfKeepsCredsOutOfArgs(t *testing.T) {
	addr := "user:Secret123@1.2.3.4:1080"

	conf := curlProxyConf("socks", addr)
	if !strings.Contains(conf, "socks5h://"+addr) {
		t.Fatalf("配置文件应包含代理地址: %q", conf)
	}

	// 非 socks/http 协议走本地无凭据 SOCKS，参数里不应出现任何账号
	args := "--socks5-hostname " + "127.0.0.1:20001"
	if strings.Contains(args, "Secret123") || strings.Contains(args, "@") {
		t.Fatalf("代理参数不应包含凭据: %q", args)
	}
	// http 用 http:// scheme
	if c := curlProxyConf("http", addr); !strings.Contains(c, "http://"+addr) {
		t.Fatalf("http 代理配置错误: %q", c)
	}
	// 其它协议不生成配置文件（返回空，走命令行参数分支）
	if c := curlProxyConf("vless", "127.0.0.1:20001"); c != "" {
		t.Fatalf("vless 不应生成 curl 配置文件: %q", c)
	}
}

// 安全响应头必须存在
func TestSecurityHeaders(t *testing.T) {
	r := newGuardRouter()
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Host = "127.0.0.1:18080"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	for k, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("响应头 %s 应为 %q，实际 %q", k, want, got)
		}
	}
}

// 超过 1MB 的请求体必须被拒绝（413），避免内存被打爆
func TestBodySizeLimit(t *testing.T) {
	r := newGuardRouter()
	big := `{"pad":"` + strings.Repeat("A", 2<<20) + `"}`
	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(big))
	req.Host = "127.0.0.1:18080"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求体应返回 413，实际 %d", w.Code)
	}
}

// 清理残余：进入 shell 的单元名必须严格白名单
func TestUnitNameWhitelist(t *testing.T) {
	ok := []string{"vpspanel-xray-443.service", "vpspanel-singbox-8443.service", "vpspanel-xray-44398.service"}
	bad := []string{
		"vpspanel-xray-443.service; rm -rf /",
		"sshd.service",
		"vpspanel-xray-abc.service",
		"vpspanel-xray-443.service\nrm -rf /tmp",
		"",
		"$(id).service",
	}
	for _, u := range ok {
		if !unitNameRe.MatchString(u) {
			t.Errorf("合法单元名被拒: %q", u)
		}
	}
	for _, u := range bad {
		if unitNameRe.MatchString(u) {
			t.Errorf("可疑单元名应被拒: %q", u)
		}
	}
}
