# syntax=docker/dockerfile:1

# 装配式镜像：二进制由 CI（reusable-image）预编译进 bin/whoami 后 COPY。
# 页面与 JS 已经通过 go:embed 内嵌进二进制，镜像里没有 Node 也没有 Go 阶段。
# 本地 `docker build` 前先跑 ./build.sh 产出 bin/whoami。
FROM alpine:3.24

# ca-certificates 只为可选的 -ip-geo-endpoint 留出口；默认零外呼时用不到，
# 但它几 KB，换来「改一个环境变量就能接归属接口」不用重新构建镜像。
RUN apk add --no-cache ca-certificates \
    && addgroup --system whoami \
    && adduser --system --ingroup whoami --home /data whoami \
    && mkdir -p /data/logs \
    && chown -R whoami:whoami /data

COPY --chmod=755 bin/whoami /usr/local/bin/whoami

# 进程内默认监听 127.0.0.1:8080（本机跑更安全），容器里必须放开到所有网卡。
# 用环境变量而不是写死 ENTRYPOINT 参数：main.go 里 flag 默认值读 env，
# 显式 -addr 仍然能覆盖，符合「flag 优先于 env」的直觉。
ENV WHOAMI_ADDR=:8080 \
    WHOAMI_LOG_DIR=/data/logs

USER whoami
WORKDIR /data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/whoami"]
