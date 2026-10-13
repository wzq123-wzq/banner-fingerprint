package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"banner-fingerprint/server/engine"
)

const (
	// maxBodyBytes 请求体上限，防止内存被恶意大包打爆。
	maxBodyBytes = 16 << 20 // 16 MiB
	// maxTargets 单次批量识别条数上限。
	maxTargets = 200_000
)

type api struct {
	engine *engine.Engine
	log    *slog.Logger
	start  time.Time
}

func (a *api) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.handleHealth)
	mux.HandleFunc("GET /rules", a.handleRules)
	mux.HandleFunc("POST /fingerprint", a.handleFingerprint)
	return a.recoverMiddleware(a.logMiddleware(mux))
}

// handleHealth 供 Docker HEALTHCHECK 与运维探活。
func (a *api) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"uptime_seconds": int(time.Since(a.start).Seconds()),
	})
}

// handleRules 展示当前已加载的规则来源与覆盖协议，自证“规则与代码解耦”。
func (a *api) handleRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.engine.RulesInfo())
}

// handleFingerprint 批量识别。请求体支持两种形态：
//
//	裸数组:   [{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-..."}, ...]
//	包装对象: {"targets":[...]}
//
// 任何单条数据都无法让服务崩溃：无法识别的条目返回 protocol="unknown"；
// 字段类型不合法的条目按空值处理，不影响同批其他条目。
func (a *api) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)

	raw, err := io.ReadAll(body)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大或读取失败")
		return
	}
	raw, err = normalizePayload(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "请求体必须是 JSON 数组或 {\"targets\":[...]}")
		return
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误: "+err.Error())
		return
	}
	if len(items) > maxTargets {
		writeErr(w, http.StatusRequestEntityTooLarge, "单次请求最多 200000 条")
		return
	}

	targets := make([]engine.Target, 0, len(items))
	for _, it := range items {
		targets = append(targets, parseTarget(it))
	}

	results := a.engine.IdentifyBatch(targets, runtime.NumCPU())
	writeJSON(w, http.StatusOK, results)
}

// normalizePayload 把 {"targets":[...]} 包装形态还原为裸数组。
func normalizePayload(raw []byte) ([]byte, error) {
	var probe struct {
		Targets json.RawMessage `json:"targets"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.Targets == nil {
		return raw, nil // 不是包装形态，按裸数组处理（后续统一校验）
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(probe.Targets, &arr); err != nil {
		return nil, err
	}
	return probe.Targets, nil
}

// parseTarget 宽松解析单条数据：个别字段类型错误的条目仍返回一个可识别对象
// （脏字段按空值处理），保证脏数据不会影响整批识别。
func parseTarget(raw json.RawMessage) engine.Target {
	t := engine.Target{}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return t // 非对象 → 全空，识别结果将是 unknown
	}
	if v, ok := m["ip"]; ok {
		_ = json.Unmarshal(v, &t.IP)
	}
	if v, ok := m["port"]; ok {
		var n json.Number
		if err := json.Unmarshal(v, &n); err == nil {
			if p, err := n.Int64(); err == nil {
				t.Port = int(p)
			}
		}
	}
	if v, ok := m["banner"]; ok {
		// 仅接受字符串；数字/null 等其他类型视为无 banner
		_ = json.Unmarshal(v, &t.Banner)
	}
	return t
}

// recoverMiddleware 兜底任何 panic：识别服务对任何输入都必须稳定返回 JSON，
// 这是“不允许崩掉”的最后一道防线。
func (a *api) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				a.log.Error("请求处理 panic 已兜底", "path", r.URL.Path, "panic", rec)
				writeErr(w, http.StatusInternalServerError, "内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// logMiddleware 结构化访问日志：方法、路径、状态码、字节数、耗时。
func (a *api) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		a.log.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"bytes", sw.n,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	n      int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.n += n
	return n, err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
