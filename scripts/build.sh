#!/usr/bin/env sh
# 产出 bin/whoami 供 Dockerfile COPY。零依赖、纯 stdlib，
# CGO_ENABLED=0 在这里是真的静态（没有 //go:linkname 到 libc 的可选绑定）。
set -e
# 脚本在 scripts/ 下，仓库根是其父目录（相对路径与 go build 包路径都以根为基准）
cd "$(dirname "$0")/.."

CGO_ENABLED=0 GOOS=linux go build -trimpath -o bin/whoami ./cmd/whoami

# 装配式镜像跑在 musl 上，产物只要还带 PT_INTERP 就会在容器里启动即 ENOENT，
# 所以本地就把这一条验掉，别等 CI 的 INTERP 守卫报红。
if command -v readelf >/dev/null 2>&1; then
    if readelf -lL bin/whoami 2>/dev/null | grep -q 'INTERP'; then
        echo "build.sh: bin/whoami 仍带 PT_INTERP，不是静态二进制" >&2
        exit 1
    fi
    echo "built bin/whoami — 静态无 INTERP"
else
    echo "built bin/whoami —（本机没有 readelf，未校验 INTERP）"
fi
