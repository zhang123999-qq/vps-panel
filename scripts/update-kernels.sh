#!/usr/bin/env bash
# scripts/update-kernels.sh —— 内嵌内核升级（维护者专用，构建期）
#
# ⚠️ 这是 P1 的 1A 能力：只由维护者在本地执行，产出新的 exe。
#    exe 运行时不得调用本脚本，也不得联网下载内核。
#
# 用法：
#   ./scripts/update-kernels.sh --xray 26.11.9 --singbox 1.14.4
#   ./scripts/update-kernels.sh --xray 26.11.9 --arch arm64      # 仅升级 xray
#   ./scripts/update-kernels.sh --rollback xray                  # 回滚到上一版
#   ./scripts/update-kernels.sh --rollback all
#
# 目录约定：
#   internal/assets/kernels/xray/<arch>/{xray.gz,version.txt}
#   internal/assets/kernels/singbox/<arch>/{sing-box.gz,version.txt}
#   备份：internal/assets/kernels/<name>/<arch>.bak-<旧版本>/
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
ASSETS="$ROOT/internal/assets/kernels"

XRAY_VER=""
SBOX_VER=""
ARCH="amd64"
ROLLBACK=""
ALLOW_NOCSUM=0

die() { echo "错误: $*" >&2; exit 1; }
log() { printf '%s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --xray)      XRAY_VER="${2:-}"; shift 2 ;;
    --singbox)   SBOX_VER="${2:-}"; shift 2 ;;
    --arch)      ARCH="${2:-}"; shift 2 ;;
    --rollback)  ROLLBACK="${2:-}"; shift 2 ;;
    --allow-no-checksum) ALLOW_NOCSUM=1; shift ;;
    -h|--help)   sed -n '1,30p' "$0"; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

case "$ARCH" in
  amd64|arm64) ;;
  *) die "不支持的架构: $ARCH（只接受 amd64 / arm64）" ;;
esac

# ── 回滚 ─────────────────────────────────────────────────────
if [ -n "$ROLLBACK" ]; then
  names=""
  case "$ROLLBACK" in
    all)   names="xray singbox" ;;
    xray)  names="xray" ;;
    singbox) names="singbox" ;;
    *) die "--rollback 只接受 xray / singbox / all" ;;
  esac
  for n in $names; do
    latest="$(ls -1d "$ASSETS/$n/$ARCH".bak-* 2>/dev/null | sort | tail -1)"
    [ -n "$latest" ] || die "$n 没有可回滚的备份"
    cp -f "$latest"/*.gz "$ASSETS/$n/$ARCH/" || die "回滚 $n 失败"
    cp -f "$latest"/version.txt "$ASSETS/$n/$ARCH/" || die "回滚 $n 版本号失败"
    log "✓ $n 已回滚到 $(cat "$ASSETS/$n/$ARCH/version.txt")（来源 $latest）"
  done
  log ""
  log "回滚完成，请重新构建：./scripts/build-windows.sh"
  exit 0
fi

[ -n "$XRAY_VER" ] || [ -n "$SBOX_VER" ] || die "至少指定 --xray 或 --singbox 的版本"
command -v curl >/dev/null || die "需要 curl"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch() { # fetch <url> <out>
  local url="$1" out="$2"
  curl -fsSL --http1.1 --retry 2 --max-time 600 -o "$out" "$url" || return 1
  [ -s "$out" ] || return 1
  return 0
}

# 备份当前版本资源
backup_current() { # backup_current <name>
  local n="$1" dir="$ASSETS/$n/$ARCH"
  [ -f "$dir/version.txt" ] || return 0
  local old; old="$(tr -d '[:space:]' < "$dir/version.txt")"
  [ -n "$old" ] || return 0
  local bdir="$ASSETS/$n/$ARCH.bak-$old"
  rm -rf "$bdir"; mkdir -p "$bdir"
  cp -f "$dir"/*.gz "$bdir"/ && cp -f "$dir/version.txt" "$bdir"/
  log "✓ 已备份 $n v$old → $(basename "$bdir")"
}

# ── Xray ────────────────────────────────────────────────────
if [ -n "$XRAY_VER" ]; then
  log "== 更新 xray → v$XRAY_VER ($ARCH) =="
  case "$ARCH" in
    amd64) FILE="Xray-linux-64.zip" ;;
    arm64) FILE="Xray-linux-arm64-v8a.zip" ;;
  esac
  MIRRORS=(
    "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VER/$FILE"
    "https://gh-proxy.com/https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VER/$FILE"
    "https://ghfast.top/https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VER/$FILE"
  )
  ok=0
  for m in "${MIRRORS[@]}"; do
    if fetch "$m" "$WORK/xray.zip"; then ok=1; break; fi
    log "  镜像失败，换下一个"
  done
  [ "$ok" = 1 ] || die "xray 下载失败（所有镜像）"

  # checksum：官方 .dgst 文件（SHA2-256= <hex>）
  if fetch "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VER/$FILE.dgst" "$WORK/xray.dgst" 2>/dev/null \
     || fetch "https://gh-proxy.com/https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VER/$FILE.dgst" "$WORK/xray.dgst" 2>/dev/null; then
    want="$(grep -iE '^SHA2-?256' "$WORK/xray.dgst" | head -1 | sed -E 's/.*[=:][[:space:]]*//' | tr -d '[:space:]')"
    got="$(sha256sum "$WORK/xray.zip" | awk '{print $1}')"
    if [ -n "$want" ]; then
      [ "$want" = "$got" ] || die "xray checksum 不匹配（期望 ${want:0:16}…，实际 ${got:0:16}…）"
      log "✓ checksum 校验通过 (${got:0:16}…)"
    elif [ "$ALLOW_NOCSUM" != 1 ]; then
      die "官方 .dgst 中没有 SHA2-256，若确认无误可加 --allow-no-checksum"
    fi
  else
    [ "$ALLOW_NOCSUM" = 1 ] || die "无法获取官方 checksum（可加 --allow-no-checksum 跳过）"
    log "! 跳过 checksum 校验（--allow-no-checksum）"
  fi

  mkdir -p "$WORK/xray" && (cd "$WORK/xray" && python3 -c "import zipfile;zipfile.ZipFile('$WORK/xray.zip').extract('xray','$WORK/xray')") \
    || die "解压 xray 失败"
  [ -s "$WORK/xray/xray" ] || die "压缩包内未找到 xray"

  backup_current xray
  gzip -9 -c "$WORK/xray/xray" > "$ASSETS/xray/$ARCH/xray.gz.tmp" || die "压缩失败"
  mv -f "$ASSETS/xray/$ARCH/xray.gz.tmp" "$ASSETS/xray/$ARCH/xray.gz"
  printf '%s\n' "$XRAY_VER" > "$ASSETS/xray/$ARCH/version.txt"
  log "✓ xray 资源已更新 → internal/assets/kernels/xray/$ARCH/"
fi

# ── sing-box ────────────────────────────────────────────────
if [ -n "$SBOX_VER" ]; then
  log "== 更新 sing-box → v$SBOX_VER ($ARCH) =="
  FILE="sing-box-$SBOX_VER-linux-$ARCH.tar.gz"
  MIRRORS=(
    "https://github.com/SagerNet/sing-box/releases/download/v$SBOX_VER/$FILE"
    "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/download/v$SBOX_VER/$FILE"
    "https://ghfast.top/https://github.com/SagerNet/sing-box/releases/download/v$SBOX_VER/$FILE"
  )
  ok=0
  for m in "${MIRRORS[@]}"; do
    if fetch "$m" "$WORK/sbox.tar.gz"; then ok=1; break; fi
    log "  镜像失败，换下一个"
  done
  [ "$ok" = 1 ] || die "sing-box 下载失败（所有镜像）"

  got="$(sha256sum "$WORK/sbox.tar.gz" | awk '{print $1}')"
  if fetch "${MIRRORS[0]}.sha256" "$WORK/sbox.sha256" 2>/dev/null; then
    want="$(awk '{print $1}' "$WORK/sbox.sha256" | head -1)"
    [ "$want" = "$got" ] || die "sing-box checksum 不匹配"
    log "✓ checksum 校验通过 (${got:0:16}…)"
  else
    log "! 官方未提供 .sha256，已记录 sha256=${got:0:32}…（可用 --allow-no-checksum 显式放行）"
    [ "$ALLOW_NOCSUM" = 1 ] || die "无法校验 sing-box 完整性（可加 --allow-no-checksum）"
  fi

  mkdir -p "$WORK/sbox"
  tar -xzf "$WORK/sbox.tar.gz" -C "$WORK/sbox" || die "解压 sing-box 失败"
  BIN="$(find "$WORK/sbox" -type f -name 'sing-box' | head -1)"
  [ -n "$BIN" ] || die "tar 包内未找到 sing-box"

  backup_current singbox
  gzip -9 -c "$BIN" > "$ASSETS/singbox/$ARCH/sing-box.gz.tmp" || die "压缩失败"
  mv -f "$ASSETS/singbox/$ARCH/sing-box.gz.tmp" "$ASSETS/singbox/$ARCH/sing-box.gz"
  printf '%s\n' "$SBOX_VER" > "$ASSETS/singbox/$ARCH/version.txt"
  log "✓ sing-box 资源已更新 → internal/assets/kernels/singbox/$ARCH/"
fi

log ""
log "完成。当前内嵌版本："
[ -f "$ASSETS/xray/$ARCH/version.txt" ] && log "  xray    $(cat "$ASSETS/xray/$ARCH/version.txt")  ($(du -h "$ASSETS/xray/$ARCH/xray.gz" | cut -f1))"
[ -f "$ASSETS/singbox/$ARCH/version.txt" ] && log "  sing-box $(cat "$ASSETS/singbox/$ARCH/version.txt")  ($(du -h "$ASSETS/singbox/$ARCH/sing-box.gz" | cut -f1))"
log ""
log "下一步：重新构建 exe"
log "  ./scripts/build-windows.sh && ./scripts/selfcheck.sh"
log "构建后 /api/health 的 kernels 字段即为新版本。"
log "回滚： ./scripts/update-kernels.sh --rollback all"
