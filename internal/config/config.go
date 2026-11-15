package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// Config 是运行时配置。数据目录优先放在 exe 同级的 data/（绿色便携），
// 不可写时回退到 %LOCALAPPDATA%\VpsPanel（下同：~/.local/share/vpspanel）。
type Config struct {
	DataDir string
	DBPath  string
	LogPath string
	Port    int
}

func Load() (*Config, error) {
	dir := os.Getenv("VPSPANEL_DATA")
	if dir == "" {
		dir = pickDataDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	port := 18080
	if v := os.Getenv("VPSPANEL_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 1024 && n < 65535 {
			port = n
		}
	}
	return &Config{
		DataDir: dir,
		DBPath:  filepath.Join(dir, "vpspanel.db"),
		LogPath: filepath.Join(dir, "vpspanel.log"),
		Port:    port,
	}, nil
}

// pickDataDir 先尝试 exe 同级 ./data，失败则用用户目录（便携 + 兼容只读安装位置）。
func pickDataDir() string {
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir := filepath.Join(filepath.Dir(exe), "data")
		if canWrite(dir) {
			return dir
		}
	}
	return userDataDir()
}

func canWrite(dir string) bool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

func userDataDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("LOCALAPPDATA"); p != "" {
			return filepath.Join(p, "VpsPanel")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "vpspanel")
}
