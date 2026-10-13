package engine

import (
	"os"
	"path/filepath"
	"testing"

	"banner-fingerprint/server/rules"
)

// TestIdentifySampleData 用题目给定的 20 条自测数据逐条断言，
// 期望值与 samples/expected.json 完全一致（含示例要求的全部输出）。
func TestIdentifySampleData(t *testing.T) {
	eng, err := Load(rules.FS, "")
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}

	cases := []struct {
		name string
		in   Target
		want Result
	}{
		{
			"OpenSSH 8.9p1 Ubuntu",
			Target{"1.2.3.4", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
			Result{"1.2.3.4", 22, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		},
		{
			"nginx 1.24.0",
			Target{"1.2.3.5", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
			Result{"1.2.3.5", 80, "HTTP", "nginx", "1.24.0", "", 0.9},
		},
		{
			"Apache 2.4.57",
			Target{"1.2.3.6", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
			Result{"1.2.3.6", 443, "HTTP", "Apache", "2.4.57", "", 0.9},
		},
		{
			"MySQL 8.0.32 二进制握手",
			Target{"1.2.3.7", 3306, "J\x00\x00\x00\n8.0.32\x00"},
			Result{"1.2.3.7", 3306, "MySQL", "MySQL", "8.0.32", "", 0.9},
		},
		{
			"Redis -ERR",
			Target{"1.2.3.8", 6379, "-ERR wrong number of arguments for 'get' command"},
			Result{"1.2.3.8", 6379, "Redis", "Redis", "", "", 0.7},
		},
		{
			"ProFTPD 1.3.7",
			Target{"1.2.3.9", 21, "220 ProFTPD 1.3.7 Server (ProFTPD)"},
			Result{"1.2.3.9", 21, "FTP", "ProFTPD", "1.3.7", "", 0.9},
		},
		{
			"Jetty 9.4.51",
			Target{"1.2.3.10", 8080, "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"},
			Result{"1.2.3.10", 8080, "HTTP", "Jetty", "9.4.51", "", 0.85},
		},
		{
			"OpenSSH 9.3 Debian",
			Target{"1.2.3.11", 22, "SSH-2.0-OpenSSH_9.3 Debian-1"},
			Result{"1.2.3.11", 22, "SSH", "OpenSSH", "9.3", "Debian", 0.95},
		},
		{
			"nginx 1.18.0 Ubuntu",
			Target{"1.2.3.12", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"},
			Result{"1.2.3.12", 80, "HTTP", "nginx", "1.18.0", "Ubuntu", 0.9},
		},
		{
			"Apache 2.4.41 Ubuntu",
			Target{"1.2.3.13", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"},
			Result{"1.2.3.13", 443, "HTTP", "Apache", "2.4.41", "Ubuntu", 0.9},
		},
		{
			"MySQL 5.7.42",
			Target{"1.2.3.14", 3306, "J\x00\x00\x00\n5.7.42\x00"},
			Result{"1.2.3.14", 3306, "MySQL", "MySQL", "5.7.42", "", 0.9},
		},
		{
			"Redis +PONG",
			Target{"1.2.3.15", 6379, "+PONG"},
			Result{"1.2.3.15", 6379, "Redis", "Redis", "", "", 0.7},
		},
		{
			"vsFTPd 3.0.5",
			Target{"1.2.3.16", 21, "220 (vsFTPd 3.0.5)"},
			Result{"1.2.3.16", 21, "FTP", "vsFTPd", "3.0.5", "", 0.9},
		},
		{
			"nginx 8443 端口",
			Target{"1.2.3.17", 8443, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"},
			Result{"1.2.3.17", 8443, "HTTP", "nginx", "1.25.3", "", 0.9},
		},
		{
			"OpenSSH 4.3 老协议",
			Target{"1.2.3.18", 22, "SSH-1.99-OpenSSH_4.3"},
			Result{"1.2.3.18", 22, "SSH", "OpenSSH", "4.3", "", 0.95},
		},
		{
			"TLS ClientHello",
			Target{"1.2.3.19", 9999, "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"},
			Result{"1.2.3.19", 9999, "TLS", "", "", "", 0.6},
		},
		{
			"Microsoft-IIS 10.0",
			Target{"1.2.3.20", 8888, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"},
			Result{"1.2.3.20", 8888, "HTTP", "Microsoft-IIS", "10.0", "", 0.9},
		},
		{
			"Redis -NOAUTH",
			Target{"1.2.3.21", 6379, "-NOAUTH Authentication required."},
			Result{"1.2.3.21", 6379, "Redis", "Redis", "", "", 0.7},
		},
		{
			"Pure-FTPd",
			Target{"1.2.3.22", 21, "220 Welcome to Pure-FTPd"},
			Result{"1.2.3.22", 21, "FTP", "Pure-FTPd", "", "", 0.75},
		},
		{
			"QUIT 无法识别",
			Target{"1.2.3.23", 12345, "QUIT\r\n"},
			Result{"1.2.3.23", 12345, "unknown", "", "", "", 0},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := eng.Identify(c.in)
			if got != c.want {
				t.Errorf("识别结果 = %+v\n期望结果 = %+v", got, c.want)
			}
		})
	}
}

// TestIdentifyEdgeCases 覆盖异常输入与隐藏验收数据可能出现的形态。
func TestIdentifyEdgeCases(t *testing.T) {
	eng, err := Load(rules.FS, "")
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}

	cases := []struct {
		name string
		in   Target
		want Result
	}{
		{"空banner+22端口兜底", Target{"a", 22, ""}, Result{"a", 22, "SSH", "", "", "", 0.35}},
		{"空banner+3306端口兜底", Target{"b", 3306, ""}, Result{"b", 3306, "MySQL", "MySQL", "", "", 0.35}},
		{"未知端口无信息", Target{"d", 1, "asdfgh"}, Result{"d", 1, "unknown", "", "", "", 0}},
		{"MariaDB 伪装 5.5.5", Target{"e", 3306, "\x4a\x00\x00\x00\n5.5.5-10.6.12-MariaDB\x00"}, Result{"e", 3306, "MySQL", "MariaDB", "10.6.12", "", 0.95}},
		{"dropbear SSH", Target{"f", 2222, "SSH-2.0-dropbear_2022.83"}, Result{"f", 2222, "SSH", "dropbear", "2022.83", "", 0.95}},
		{"Tomcat Apache-Coyote", Target{"g", 8080, "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1"}, Result{"g", 8080, "HTTP", "Tomcat", "", "", 0.7}},
		{"Redis INFO 含版本", Target{"h", 6379, "$1942\r\n# Server\r\nredis_version:7.0.8\r\n"}, Result{"h", 6379, "Redis", "Redis", "7.0.8", "", 0.95}},
		{"SMTP Postfix", Target{"i", 25, "220 mail.test ESMTP Postfix 3.5.8"}, Result{"i", 25, "SMTP", "Postfix", "3.5.8", "", 0.9}},
		{"PostgreSQL FATAL", Target{"j", 5432, `EFATAL: password authentication failed for user "x"`}, Result{"j", 5432, "PostgreSQL", "PostgreSQL", "", "", 0.7}},
		{"HTTP 请求首行", Target{"k", 80, "GET / HTTP/1.1\r\nHost: test\r\n"}, Result{"k", 80, "HTTP", "", "", "", 0.6}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := eng.Identify(c.in)
			if got != c.want {
				t.Errorf("识别结果 = %+v\n期望结果 = %+v", got, c.want)
			}
		})
	}
}

// TestIdentifyBatchKeepsOrder 批量识别必须保持输入顺序且逐条结果正确。
func TestIdentifyBatchKeepsOrder(t *testing.T) {
	eng, err := Load(rules.FS, "")
	if err != nil {
		t.Fatal(err)
	}
	targets := []Target{
		{"a", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"b", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"},
		{"c", 3306, "J\x00\x00\x00\n8.0.32\x00"},
		{"d", 6379, "+PONG"},
		{"e", 21, "220 ProFTPD 1.3.7 Server (ProFTPD)"},
	}
	results := eng.IdentifyBatch(targets, 4)
	wantProtocols := []string{"SSH", "HTTP", "MySQL", "Redis", "FTP"}
	for i, want := range wantProtocols {
		if results[i].Protocol != want {
			t.Errorf("第 %d 条协议 = %s, 期望 %s", i, results[i].Protocol, want)
		}
		if results[i].IP != targets[i].IP || results[i].Port != targets[i].Port {
			t.Errorf("第 %d 条 ip/port 回显不一致: %+v", i, results[i])
		}
	}
}

// TestExternalRuleOverride 验证外部规则目录可覆盖内嵌规则（规则与代码解耦）。
func TestExternalRuleOverride(t *testing.T) {
	dir := t.TempDir()
	override := `version: 1
protocols:
  - name: SSH
    priority: 100
    matcher: '^SSH-\d'
    protocol_confidence: 0.42
    products:
      - product: OpenSSH
        regex: 'OpenSSH[_-](?P<version>\d+(?:\.\d+)*)'
        confidence: 0.42
`
	if err := os.WriteFile(filepath.Join(dir, "override.yaml"), []byte(override), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(rules.FS, dir)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	got := eng.Identify(Target{"x", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"})
	if got.Confidence != 0.42 {
		t.Errorf("外部规则未覆盖内置规则: %+v", got)
	}
}

// TestBrokenExternalRuleIsIgnored 坏的外部规则不应导致服务不可用。
func TestBrokenExternalRuleIsIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("protocols: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(rules.FS, dir)
	if err != nil {
		t.Fatalf("坏的外部规则不应导致加载失败: %v", err)
	}
	got := eng.Identify(Target{"x", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"})
	if got.Protocol != "SSH" {
		t.Errorf("内嵌规则应仍然可用: %+v", got)
	}
}
