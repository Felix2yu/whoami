#!/usr/bin/env bash
# whoami 构建脚本 —— 产出静态单二进制供 Dockerfile COPY。
#
# 产物：bin/whoami（GOOS=linux、CGO 关闭；macOS 上不能直接运行，这是给镜像用的）
# 前置：Go
#
# 用法：
#   ./scripts/build.sh
#   GO_BIN=/path/to/go ./scripts/build.sh
#
# 约定见 Felix2yu/.github/docs/build-script.md
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
die() { printf '\033[1;31m错误：\033[0m %s\n' "$1" >&2; exit 1; }

if [ -z "${GO_BIN:-}" ]; then
  if command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
  elif [ -x /opt/homebrew/bin/go ]; then
    GO_BIN=/opt/homebrew/bin/go
  elif [ -x /usr/local/go/bin/go ]; then
    GO_BIN=/usr/local/go/bin/go
  else
    die "找不到 go，可显式指定：GO_BIN=/path/to/go $0"
  fi
fi
[ -x "$GO_BIN" ] || die "GO_BIN 不可执行：$GO_BIN"

step "[1/2] 构建静态二进制（GOOS=linux，CGO 关闭）"
mkdir -p "$ROOT/bin"
# 零依赖、纯 stdlib：CGO_ENABLED=0 在这里是真的静态（没有 //go:linkname 到 libc 的可选绑定）。
CGO_ENABLED=0 GOOS=linux "$GO_BIN" build -trimpath -o "$ROOT/bin/whoami" ./cmd/whoami

step "[2/2] 校验没有 PT_INTERP"
# 装配式镜像跑在 musl 上，产物只要还带 PT_INTERP 就会在容器里启动即 ENOENT，
# 所以本地就把这一条验掉，别等 CI 的 INTERP 守卫报红。
if command -v readelf >/dev/null 2>&1; then
  if readelf -lL "$ROOT/bin/whoami" 2>/dev/null | grep -q 'INTERP'; then
    die "bin/whoami 仍带 PT_INTERP，不是静态二进制"
  fi
  printf '  bin/whoami 静态无 INTERP\n'
else
  printf '  本机没有 readelf，跳过 INTERP 校验\n'
fi

printf '\n完成：%s\n' "$ROOT/bin/whoami"
