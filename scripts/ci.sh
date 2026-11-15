#!/usr/bin/env bash
# scripts/ci.sh —— 一条命令跑完所有质量门（本地/CI 通用）
#
#   ./scripts/ci.sh          # 静态检查 + 单测 + 双平台编译
#   E2E=1 ./scripts/ci.sh    # 追加端到端回归（需 PANEL / SERVER_ID）
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
export PATH="/usr/local/go/bin:$PATH"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"

fail=0
step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

step "1/5 gofmt"
unformatted=$(gofmt -l . 2>/dev/null)
if [ -n "$unformatted" ]; then echo "$unformatted"; fail=1; else echo "OK"; fi

step "2/5 go vet"
if go vet ./... 2>&1 | grep -q .; then fail=1; else echo "OK"; fi

step "3/5 单元测试"
if go test ./... 2>&1 | tee /tmp/vpspanel-test.log | grep -q "FAIL"; then
  grep "FAIL" /tmp/vpspanel-test.log; fail=1
else
  grep -c "^ok" /tmp/vpspanel-test.log | xargs -I{} echo "通过 {} 个包"
fi

step "4/5 交叉编译"
if CGO_ENABLED=0 GOOS=linux go build -o /tmp/vp-ci-linux ./cmd/vps-panel; then echo "linux OK"; else fail=1; fi
if CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /tmp/vp-ci.exe ./cmd/vps-panel; then echo "windows OK"; else fail=1; fi

step "5/5 敏感信息 / 危险命令"
if grep -rnE '(password|secret|token)[[:space:]]*[:=][[:space:]]*"[^"]{3,}"' --include='*.go' internal/ 2>/dev/null \
   | grep -vE 'json:"|//|placeholder' | grep -q .; then echo "发现疑似明文凭据"; fail=1; else echo "OK"; fi
if grep -rnE 'rm -rf /[a-z]' --include='*.go' internal/ 2>/dev/null | grep -v '_test\.go' | grep -q .; then echo "发现危险命令"; fail=1; else echo "OK"; fi

if [ "${E2E:-0}" = "1" ]; then
  step "附加：端到端回归"
  PANEL="${PANEL:-http://127.0.0.1:18080}" SERVER_ID="${SERVER_ID:-1}" ./scripts/e2e.sh || fail=1
fi

step "结果"
[ "$fail" -eq 0 ] && { echo "全部通过 ✅"; exit 0; } || { echo "存在问题 ❌"; exit 1; }
