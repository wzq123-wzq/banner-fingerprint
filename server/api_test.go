package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"banner-fingerprint/server/engine"
	"banner-fingerprint/server/rules"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	eng, err := engine.Load(rules.FS, "")
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	a := &api{engine: eng, log: slog.New(slog.NewTextHandler(io.Discard, nil)), start: time.Now()}
	return httptest.NewServer(a.routes())
}

func postFingerprint(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url+"/fingerprint", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /fingerprint: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应: %v", err)
	}
	return resp, data
}

// TestFingerprintRecognizesKnownBanners 覆盖题目要求的全部五类协议。
func TestFingerprintRecognizesKnownBanners(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	body := `[
	  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"},
	  {"ip":"1.2.3.7","port":3306,"banner":"J\u0000\u0000\u0000\n8.0.32\u0000"},
	  {"ip":"1.2.3.8","port":6379,"banner":"-ERR wrong number of arguments for 'get' command"},
	  {"ip":"1.2.3.9","port":21,"banner":"220 ProFTPD 1.3.7 Server (ProFTPD)"}
	]`
	resp, data := postFingerprint(t, srv.URL, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, 响应 = %s", resp.StatusCode, data)
	}
	var results []engine.Result
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("解析响应: %v", err)
	}
	want := []struct{ protocol, product, version, osHint string }{
		{"SSH", "OpenSSH", "8.9p1", "Ubuntu"},
		{"HTTP", "nginx", "1.24.0", ""},
		{"MySQL", "MySQL", "8.0.32", ""},
		{"Redis", "Redis", "", ""},
		{"FTP", "ProFTPD", "1.3.7", ""},
	}
	if len(results) != len(want) {
		t.Fatalf("结果条数 = %d, 期望 %d", len(results), len(want))
	}
	for i, w := range want {
		r := results[i]
		if r.Protocol != w.protocol || r.Product != w.product || r.Version != w.version || r.OSHint != w.osHint {
			t.Errorf("第 %d 条 = %+v, 期望 %+v", i, r, w)
		}
	}
}

// TestFingerprintWrappedPayload 兼容 {"targets":[...]} 包装形态。
func TestFingerprintWrappedPayload(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	body := `{"targets":[{"ip":"1.2.3.15","port":6379,"banner":"+PONG"}]}`
	resp, data := postFingerprint(t, srv.URL, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, 响应 = %s", resp.StatusCode, data)
	}
	var results []engine.Result
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Protocol != "Redis" {
		t.Errorf("结果 = %+v", results)
	}
}

// TestFingerprintUnknownDoesNotFail 认不出来返回 unknown，绝不报错。
func TestFingerprintUnknownDoesNotFail(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	body := `[{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"},{"ip":"x","port":1,"banner":""}]`
	resp, data := postFingerprint(t, srv.URL, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, 响应 = %s", resp.StatusCode, data)
	}
	var results []engine.Result
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Protocol != "unknown" || r.Confidence != 0 {
			t.Errorf("应为 unknown: %+v", r)
		}
	}
}

// TestFingerprintMalformedJSON 畸形请求返回结构化 400，不崩。
func TestFingerprintMalformedJSON(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	resp, data := postFingerprint(t, srv.URL, "not-json")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, 响应 = %s", resp.StatusCode, data)
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &e); err != nil || e.Error == "" {
		t.Errorf("应返回 JSON 错误信息: %s", data)
	}
}

// TestFingerprintDirtyItemStillServes 脏字段的条目按空值处理，不影响整批。
func TestFingerprintDirtyItemStillServes(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	body := `[{"ip":"a","port":"not-a-number","banner":123},{"ip":"1.2.3.8","port":6379,"banner":"+PONG"}]`
	resp, data := postFingerprint(t, srv.URL, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("脏数据不应导致整批失败: %d %s", resp.StatusCode, data)
	}
	var results []engine.Result
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Protocol != "unknown" || results[1].Protocol != "Redis" {
		t.Errorf("结果 = %+v", results)
	}
}

func TestFingerprintEmptyArray(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	resp, data := postFingerprint(t, srv.URL, "[]")
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(data)) != "[]" {
		t.Errorf("空数组响应异常: %d %s", resp.StatusCode, data)
	}
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), `"ok"`) {
		t.Errorf("响应 = %s", data)
	}
}

// TestRulesEndpoint 规则摘要接口应列出全部协议，自证规则解耦。
func TestRulesEndpoint(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/rules")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	for _, p := range []string{"SSH", "HTTP", "MySQL", "Redis", "FTP"} {
		if !strings.Contains(string(data), p) {
			t.Errorf("规则列表缺少 %s: %s", p, data)
		}
	}
}
