// Package kernel 在内嵌资源之上提供版本信息与自检。
//
// P1：对内可升级（构建期 scripts/update-kernels.sh），对外锁死（运行期不下载）。
package kernel

import (
	"fmt"

	"vpspanel/internal/assets"
)

// XrayVersion 内嵌 xray 版本（唯一来源：internal/assets）。
var XrayVersion = assets.XrayVersion()

// SingboxVersion 内嵌 sing-box 版本。
var SingboxVersion = assets.SingboxVersion()

// Arch 内嵌资源架构。
func Arch() string { return assets.Arch() }

// XrayGz 返回内嵌 xray 压缩包。
func XrayGz() []byte { return assets.XrayGzAmd64 }

// SingboxGz 返回内嵌 sing-box 压缩包。
func SingboxGz() []byte { return assets.SingboxGzAmd64 }

// Check 启动时校验内嵌资源完整性。
func Check() error {
	if XrayVersion == "" || SingboxVersion == "" {
		return fmt.Errorf("内嵌内核版本号缺失（version.txt）")
	}
	if len(XrayGz()) < 1<<20 || len(SingboxGz()) < 1<<20 {
		return fmt.Errorf("内嵌内核资源过小，可能损坏（xray=%d, singbox=%d 字节）", len(XrayGz()), len(SingboxGz()))
	}
	return nil
}

// Builtin 返回内嵌版本信息（/api/health 与 UI 展示用）。
func Builtin() map[string]string {
	return map[string]string{
		"xray":    XrayVersion,
		"singbox": SingboxVersion,
		"arch":    Arch(),
	}
}
