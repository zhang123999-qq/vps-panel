package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestFindRunningPanel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("解析测试地址失败: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(u.Port(), "%d", &port)

	got := findRunningPanel(port)
	if got == "" {
		t.Fatal("应能探测到运行中的面板实例")
	}
	if got != fmt.Sprintf("http://127.0.0.1:%d", port) {
		t.Fatalf("返回地址不正确: %s", got)
	}

	// 扫描一个几乎没有服务的区间，应返回空
	if got := findRunningPanel(port + 3000); got != "" {
		t.Fatalf("不应探测到不存在的实例，却返回 %s", got)
	}
}
