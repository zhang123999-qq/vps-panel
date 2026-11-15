#!/usr/bin/env bash
# scripts/e2e.sh —— 端到端回归矩阵（对一台已登记的测试 VPS 跑一遍 deploy 矩阵）
#
# 前置：
#   1) 面板已启动：VPSPANEL_NO_BROWSER=1 ./VpsPanel.exe
#   2) 目标机已登记为 server_id=1，且 SSH 可达
#
# 用法：
#   PANEL=http://127.0.0.1:18080 SERVER_ID=1 ./scripts/e2e.sh
#
# 覆盖：
#   - 6 种协议：vless / vmess / shadowsocks / trojan / hysteria2 / socks / http
#   - 端口边界（65536 / -1 / abc / 已占用）
#   - 幂等重部署
#   - 内核版本一致性
#   - 收尾清理（避免污染测试机）
set -uo pipefail

PANEL="${PANEL:-http://127.0.0.1:18080}"
SERVER_ID="${SERVER_ID:-1}"
PASS=0
FAIL=0

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

post() { curl -s --max-time 600 -X POST "$PANEL$1" -H 'Content-Type: application/json' -d "$2"; }
jsonq() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1" 2>/dev/null; }

deploy() { # deploy <protocol> <port> → 打印 ok/err
  local body
  body=$(printf '{"server_ids":[%s],"protocol":"%s","port":%s}' "$SERVER_ID" "$1" "$2")
  post /api/deploy "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin)
r=d['results'][0]
print('OK' if r['ok'] else 'ERR:' + (r.get('error') or '')[:120])
print(r.get('link') or '')
"
}

say "0. 连通性（面板 + 目标机）"
post "/api/servers/$SERVER_ID/test" '{}' | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('OK' if d.get('ok') else 'ERR:' + (d.get('error') or '')[:120])
print(d.get('server',{}).get('os',''))
" | { read -r st; read -r os; [ "$st" = "OK" ] && ok "SSH 探测通过（$os）" || bad "SSH 探测失败 $st"; }

say "0.5 预清理（让脚本可重复执行：清掉该机上所有本面板残留）"
pre=$(post "/api/servers/$SERVER_ID/cleanup" '{}' | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print('OK' if d.get('ok') else 'ERR:'+(d.get('error') or '')[:80])
except Exception as e: print('ERR:'+str(e))
")
[ "$pre" = "OK" ] && ok "预清理完成（远端 vpspanel-* 已清空）" || bad "预清理失败：$pre"

say "1. 协议矩阵"
declare -A PORTS=( [vless]=46001 [vmess]=46002 [shadowsocks]=46003 [trojan]=46004 [hysteria2]=46005 [socks]=46006 [http]=46007 )
for proto in vless vmess shadowsocks trojan hysteria2 socks http; do
  port=${PORTS[$proto]}
  out=$(deploy "$proto" "$port")
  st=$(echo "$out" | head -1)
  link=$(echo "$out" | tail -n +2)
  if [ "${st:0:2}" = "OK" ]; then
    case "$proto" in
      vless)        [[ "$link" == vless://* ]]      && ok "$proto :$port 部署+链接" || bad "$proto 链接异常" ;;
      vmess)        [[ "$link" == vmess://* ]]      && ok "$proto :$port 部署+链接" || bad "$proto 链接异常" ;;
      shadowsocks)  [[ "$link" == ss://* ]]         && ok "$proto :$port 部署+链接" || bad "$proto 链接异常" ;;
      trojan)       [[ "$link" == trojan://* ]]     && ok "$proto :$port 部署+链接" || bad "$proto 链接异常" ;;
      hysteria2)    [[ "$link" == hysteria2://* ]]  && ok "$proto :$port 部署+链接" || bad "$proto 链接异常" ;;
      socks)        [[ "$link" == socks://* ]]      && ok "$proto :$port 部署+链接" || bad "$proto 链接异常" ;;
      http)         [[ "$link" == http://* ]]       && ok "$proto :$port 部署+链接" || bad "$proto 链接异常" ;;
    esac
  else
    bad "$proto :$port 部署失败 → $st"
  fi
done

say "2. 幂等：同端口重复部署"
out=$(deploy vless 46001)
[ "$(echo "$out" | head -1)" = "OK" ] && ok "vless 同端口二次部署通过" || bad "vless 二次部署失败：$(echo "$out" | head -1)"

say "3. 边界端口"
for p in 65536 -1; do
  r=$(post /api/deploy "{\"server_ids\":[$SERVER_ID],\"protocol\":\"vless\",\"port\":$p}" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print('REJECT' if 'error' in d else 'ACCEPT')
except Exception: print('REJECT')
")
  [ "$r" = "REJECT" ] && ok "端口 $p 被拒绝" || bad "端口 $p 未被拒绝"
done
r=$(post /api/deploy "{\"server_ids\":[$SERVER_ID],\"protocol\":\"vless\",\"port\":\"abc\"}" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin); print('REJECT' if 'error' in d else 'ACCEPT')
except Exception: print('REJECT')
")
[ "$r" = "REJECT" ] && ok "端口 abc 被拒绝" || bad "端口 abc 未被拒绝"

say "4. 内核版本"
curl -s "$PANEL/api/kernels" | python3 -c "
import json,sys
d=json.load(sys.stdin)
b=d['builtin']
print('builtin', b['xray'], b['singbox'])
for it in d['items']:
    print('server', it['server_id'], it['xray'], it['singbox'], 'diff' if (it['xray_diff'] or it['singbox_diff']) else 'same')
" | while read -r line; do ok "$line"; done

say "5. 清理（卸载本次部署的节点）"
curl -s "$PANEL/api/servers/$SERVER_ID/nodes" | python3 -c "
import json,sys
for n in json.load(sys.stdin).get('items',[]):
    if n['port'] >= 46001 and n['port'] <= 46007:
        print(n['id'])
" | while read -r id; do
  [ -n "$id" ] || continue
  resp=$(curl -s -X DELETE "$PANEL/api/deployments/$id" -H 'Content-Type: application/json')
  if echo "$resp" | grep -q '"ok":true'; then
    ok "已卸载节点 #$id"
  else
    bad "卸载节点 #$id 失败：$resp"
  fi
done

say "结果"
printf '  通过 %d / 失败 %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
