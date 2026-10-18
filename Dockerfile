# syntax=docker/dockerfile:1

# 装配式镜像：二进制由 CI（reusable-image）预编译进 bin/whoami 后 COPY。
# 页面与 JS 已经通过 go:embed 内嵌进二进制，镜像里没有 Node 也没有 Go 阶段。
# 本地 `docker build` 前先跑 ./build.sh 产出 bin/whoami。
#
# 基镜 ghcr.io/felix2yu/base:alpine-3.24 提供 ca-certificates（只为可选的
# -ip-geo-endpoint 留出口）、tzdata、su-exec 与 PUID/PGID 降权入口；
# 原先的 `USER whoami` 由基镜入口的降权取代。
FROM ghcr.io/felix2yu/base:alpine-3.24

RUN mkdir -p /data/logs

COPY --chmod=755 bin/whoami /usr/local/bin/whoami

# 进程内默认监听 127.0.0.1:8080（本机跑更安全），容器里必须放开到所有网卡。
# 用环境变量而不是写死 CMD 参数：main.go 里 flag 默认值读 env，显式 -addr 仍可覆盖。
ENV WHOAMI_ADDR=:8080 \
    WHOAMI_LOG_DIR=/data/logs \
    APP_DATA_DIR=/data

WORKDIR /data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

CMD ["/usr/local/bin/whoami"]
