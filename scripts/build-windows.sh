#!/usr/bin/env bash
# 交叉编译 Windows 单文件 exe（CGO 关闭，纯 Go SQLite 驱动，无 MSVC 依赖）
# 注意：不加 -H windowsgui —— 需求是「双击启动命令行工具」，保留控制台窗口显示状态与日志。
set -euo pipefail

cd "$(dirname "$0")/.."

export PATH="/usr/local/go/bin:$PATH"
export CGO_ENABLED=0
export GOOS=windows
export GOARCH=amd64
export GOFLAGS="-mod=mod"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"

VERSION="${VERSION:-0.2.0-m1}"
OUT="dist/VpsPanel.exe"

mkdir -p dist
go build -trimpath \
  -ldflags "-s -w -X vpspanel/internal/api.Version=${VERSION}" \
  -o "$OUT" ./cmd/vps-panel

echo "built: $OUT ($(du -h "$OUT" | cut -f1))"
