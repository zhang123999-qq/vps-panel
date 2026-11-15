package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vpspanel/internal/api"
	"vpspanel/internal/config"
	"vpspanel/internal/crypto"
	"vpspanel/internal/kernel"
	"vpspanel/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 日志同时写文件（打包成 windowsgui 后没有控制台，文件是唯一排障途径）
	if lf, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		log.SetOutput(io.MultiWriter(os.Stdout, lf))
		defer lf.Close()
	}

	// P1：内嵌内核自检（资源缺失/损坏应启动即失败，而不是部署时才炸）
	if err := kernel.Check(); err != nil {
		log.Fatalf("内嵌内核自检失败: %v", err)
	}
	log.Printf("内嵌内核: xray %s / sing-box %s (%s)", kernel.XrayVersion, kernel.SingboxVersion, kernel.Arch())

	// 单实例锁：绑定 127.0.0.1:(port-1)。进程崩溃/退出时内核自动释放，不会留下死锁文件。
	lockPort := cfg.Port - 1
	lockLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lockPort))
	if err != nil {
		if existing := existingInstance(cfg.DataDir, cfg.Port); existing != "" {
			log.Printf("检测到已在运行的 VpsPanel：%s（本次不重复启动）", existing)
			if os.Getenv("VPSPANEL_NO_BROWSER") == "" {
				openBrowser(existing)
			}
			return
		}
		log.Fatalf("单实例锁端口 %d 被占用，且未探测到已运行的面板", lockPort)
	}
	defer lockLn.Close()

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	log.Printf("数据库就绪: %s", cfg.DBPath)

	box, err := crypto.LoadOrCreate(cfg.DataDir)
	if err != nil {
		log.Fatalf("初始化密钥失败: %v", err)
	}
	log.Printf("凭证加密已启用: %s", cfg.DataDir)

	port, err := pickPort(cfg.Port)
	if err != nil {
		log.Fatalf("%v", err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	srv := &http.Server{
		Handler:           api.New(db, cfg, box),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP 服务异常: %v", err)
		}
	}()

	// 记录实际端口：第二个实例启动时可直接跳到正确地址，而不是盲扫
	_ = os.WriteFile(instancePortFile(), []byte(strconv.Itoa(port)), 0o600)

	log.Printf("VpsPanel %s 已启动: %s", api.Version, url)
	if os.Getenv("VPSPANEL_NO_BROWSER") == "" {
		openBrowser(url)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("正在关闭...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// pickPort 从起始端口向上找一个空闲端口，避免 18080 被占用时启动失败。
func pickPort(start int) (int, error) {
	for p := start; p < start+20; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			_ = ln.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("端口 %d-%d 全部被占用", start, start+19)
}

// instancePortFile 放在系统临时目录（Windows 下为 %TEMP%），与数据目录解耦。
func instancePortFile() string { return filepath.Join(os.TempDir(), "vpspanel.instance.port") }

// existingInstance 优先读 instance.port，读不到再扫描端口段。
func existingInstance(dataDir string, start int) string {
	if raw, err := os.ReadFile(instancePortFile()); err == nil {
		if p, e := strconv.Atoi(strings.TrimSpace(string(raw))); e == nil && p > 0 && p < 65536 {
			u := fmt.Sprintf("http://127.0.0.1:%d", p)
			if healthOK(u) {
				return u
			}
		}
	}
	return findRunningPanel(start)
}

// healthOK 探测某个地址是否是活的 VpsPanel。
func healthOK(base string) bool {
	cli := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := cli.Get(base + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// findRunningPanel 在 18080..18099 里找已经响应的面板。
func findRunningPanel(start int) string {
	cli := &http.Client{Timeout: 800 * time.Millisecond}
	for p := start; p < start+20; p++ {
		u := fmt.Sprintf("http://127.0.0.1:%d", p)
		resp, err := cli.Get(u + "/api/health")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return u
		}
	}
	return ""
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("打开浏览器失败（请手动访问 %s）: %v", url, err)
	}
}
