#!/usr/bin/env bash
# 项目自检脚本：格式、静态检查、编译、敏感信息扫描。
# 用法： ./scripts/selfcheck.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
export PATH="/usr/local/go/bin:$PATH"
export GOFLAGS="-mod=mod"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"

fail=0
say() { printf '\n== %s ==\n' "$1"; }

say "gofmt（未格式化的文件应为空）"
unformatted=$(gofmt -l . 2>/dev/null)
if [ -n "$unformatted" ]; then
  echo "$unformatted"
  fail=1
else
  echo "OK"
fi

say "go vet"
if go vet ./... 2>&1 | tee /tmp/vpspanel-vet.log | grep -q .; then
  fail=1
else
  echo "OK"
fi

say "编译（linux + windows 交叉）"
if CGO_ENABLED=0 go build -o /tmp/vpspanel-check ./cmd/vps-panel; then
  echo "linux OK"
else
  echo "linux FAILED"; fail=1
fi
if CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /tmp/vpspanel-check.exe ./cmd/vps-panel; then
  echo "windows OK"
else
  echo "windows FAILED"; fail=1
fi

say "敏感信息扫描（源码中不应出现明文口令）"
hits=$(grep -rnE '(password|passwd|secret|token)[[:space:]]*[:=][[:space:]]*"[^"]{3,}"' \
        --include='*.go' . 2>/dev/null | grep -vE 'json:"|//|placeholder|example' || true)
if [ -n "$hits" ]; then
  echo "$hits"; fail=1
else
  echo "OK"
fi

say "危险命令扫描（代码中不应存在 rm -rf / 等）"
if grep -rnE 'rm -rf /[a-z]' --include='*.go' . 2>/dev/null | grep -v '_test\.go' | grep -q .; then
  echo "发现危险命令，请人工确认"; fail=1
else
  echo "OK"
fi

say "文档与帮助同步检查"
for f in README.md docs/ops.md docs/architecture.md; do
  [ -f "$f" ] && echo "found $f" || { echo "missing $f"; fail=1; }
done

say "结果"
if [ "$fail" -eq 0 ]; then
  echo "全部通过 ✅"
else
  echo "存在问题 ❌"
fi
exit "$fail"
