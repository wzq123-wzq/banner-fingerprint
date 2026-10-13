// Banner 指纹识别服务端。
//
// 用法:
//
//	./server                # 启动 API 服务（监听 LISTEN_ADDR，默认 :8080）
//	./server -healthcheck   # 自检模式：探测本机 /health，供 Docker HEALTHCHECK 使用
//
// 环境变量:
//
//	LISTEN_ADDR  监听地址（默认 :8080）
//	RULES_DIR    外部规则目录（可选；同名协议覆盖内置规则、新协议追加，无需重编译）
//	LOG_LEVEL    日志级别 debug|info|warn|error（默认 info）
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"banner-fingerprint/server/engine"
	"banner-fingerprint/server/rules"
)

func main() {
	// 健康检查自检模式（scratch 镜像无 shell/curl，用二进制自身探活）
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	listen := envOr("LISTEN_ADDR", ":8080")
	rulesDir := envOr("RULES_DIR", "")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(envOr("LOG_LEVEL", "info")),
	}))
	slog.SetDefault(logger)

	eng, err := engine.Load(rules.FS, rulesDir)
	if err != nil {
		logger.Error("规则加载失败", "err", err)
		os.Exit(1)
	}
	info := eng.RulesInfo()
	logger.Info("规则加载完成", "sources", info.Sources, "protocols", len(info.Protocols))

	a := &api{engine: eng, log: logger, start: time.Now()}
	srv := &http.Server{
		Addr:              listen,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("服务启动", "addr", listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		logger.Error("服务异常退出", "err", err)
		os.Exit(1)
	case <-ctx.Done():
		logger.Info("收到退出信号，开始优雅停机")
	}

	// 优雅停机：等待在途请求处理完成，最多 10s
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("优雅停机超时，强制退出", "err", err)
		os.Exit(1)
	}
	logger.Info("服务已退出")
}

// healthcheck 探测本机 /health，成功返回退出码 0。
func healthcheck() int {
	listen := envOr("LISTEN_ADDR", ":8080")
	port := "8080"
	if i := strings.LastIndex(listen, ":"); i >= 0 && listen[i+1:] != "" {
		port = listen[i+1:]
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck 失败:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck 失败: status", resp.StatusCode)
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
