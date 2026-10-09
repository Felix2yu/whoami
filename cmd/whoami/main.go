package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"whoami/internal/whoami"
)

func main() {
	cfg := whoami.DefaultConfig()
	addr := flag.String("addr", envOr("WHOAMI_ADDR", cfg.Addr), "监听地址")
	proxies := flag.String("trusted-proxies", envOr("WHOAMI_TRUSTED_PROXIES", ""), "受信反向代理 CIDR，逗号分隔；留空表示不信任任何代理头")
	ipDict := flag.String("ip-dict", envOr("WHOAMI_IP_DICT", ""), "IP 归属字典路径，格式为每行 `CIDR,标签`，改完约 10 秒内自动生效")
	ancestors := flag.String("frame-ancestors", envOr("WHOAMI_FRAME_ANCESTORS", ""), "允许 iframe 嵌入的来源白名单，空格或逗号分隔；留空表示不限")
	logDir := flag.String("log-dir", envOr("WHOAMI_LOG_DIR", cfg.LogDir), "访问日志目录，留空表示不落盘")
	keepDays := flag.Int("log-keep-days", envIntOr("WHOAMI_LOG_KEEP_DAYS", cfg.LogKeepDays), "启动时清理超过该天数的日志，0 表示不清理")
	anon := flag.String("anonymize-ip", envOr("WHOAMI_ANONYMIZE_IP", cfg.AnonymizeIP), "日志与统计里的地址脱敏：off|last-octet|full")
	replayDays := flag.Int("stats-replay-days", envIntOr("WHOAMI_STATS_REPLAY_DAYS", cfg.StatsReplayDays), "启动时回放最近多少天日志重建统计")
	flag.Parse()
	cfg.Addr = *addr
	cfg.TrustedProxies = splitList(*proxies)
	cfg.IPDictPath = *ipDict
	cfg.FrameAncestors = splitList(*ancestors)
	cfg.LogDir = *logDir
	cfg.LogKeepDays = *keepDays
	cfg.AnonymizeIP = *anon
	cfg.StatsReplayDays = *replayDays

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	srv, err := whoami.NewServer(cfg)
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	httpSrv := srv.HTTPServer()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", srv.Addr())
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown failed", "err", err)
			os.Exit(1)
		}
		if err := srv.Close(); err != nil {
			logger.Error("close log failed", "err", err)
		}
		logger.Info("shutdown complete")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
