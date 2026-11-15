// Package assets 内嵌构建期资源（内核二进制）。
//
// 资源目录约定（由 scripts/update-kernels.sh 维护）：
//
//	kernels/xray/<arch>/xray.gz        + version.txt
//	kernels/singbox/<arch>/sing-box.gz + version.txt
//
// 运行期只读，绝不联网下载（P1）。
package assets

import (
	_ "embed"
	"strings"
)

//go:embed kernels/xray/amd64/xray.gz
var XrayGzAmd64 []byte

//go:embed kernels/xray/amd64/version.txt
var xrayVer string

//go:embed kernels/singbox/amd64/sing-box.gz
var SingboxGzAmd64 []byte

//go:embed kernels/singbox/amd64/version.txt
var singboxVer string

// XrayVersion 内嵌 xray 版本。
func XrayVersion() string { return strings.TrimSpace(xrayVer) }

// SingboxVersion 内嵌 sing-box 版本。
func SingboxVersion() string { return strings.TrimSpace(singboxVer) }

// Arch 内嵌资源目标架构。
func Arch() string { return "amd64" }
