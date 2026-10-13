// Banner 指纹识别客户端：读取本地 JSON 原始数据文件 → 发送到识别服务 → 展示结果。
//
// 用法:
//
//	banner-client -file samples/banners.json -server http://server:8080
//	banner-client -json -file banners.json        # 输出原始 JSON（适合管道/程序消费）
//
// 环境变量: INPUT_FILE、SERVER_URL、TIMEOUT_SECONDS、RETRIES。
//
// 退出码: 0 成功；1 文件读取 / 网络 / 服务端错误。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"banner-fingerprint/server/engine"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		filePath = flag.String("file", envOr("INPUT_FILE", "banners.json"), "本地原始数据 JSON 文件路径")
		server   = flag.String("server", envOr("SERVER_URL", "http://localhost:8080"), "识别服务地址")
		asJSON   = flag.Bool("json", false, "以 JSON 形式输出结果（默认表格）")
		timeoutS = flag.Int("timeout", envIntOr("TIMEOUT_SECONDS", 15), "HTTP 超时（秒）")
		retries  = flag.Int("retries", envIntOr("RETRIES", 3), "连接失败重试次数")
	)
	flag.Parse()

	data, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取输入文件失败: %v\n", err)
		return 1
	}
	if !json.Valid(data) {
		fmt.Fprintln(os.Stderr, "输入文件不是合法 JSON")
		return 1
	}

	client := &http.Client{Timeout: time.Duration(*timeoutS) * time.Second}
	var resp *http.Response
	for attempt := 1; ; attempt++ {
		resp, err = client.Post(*server+"/fingerprint", "application/json", bytes.NewReader(data))
		if err == nil {
			break
		}
		if attempt >= *retries {
			fmt.Fprintf(os.Stderr, "请求识别服务 %s 失败（已重试 %d 次）: %v\n", *server, attempt-1, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "连接失败，2s 后重试（%d/%d）: %v\n", attempt, *retries, err)
		time.Sleep(2 * time.Second)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取响应失败: %v\n", err)
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "识别服务返回错误: HTTP %d\n%s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	if *asJSON {
		var buf bytes.Buffer
		if err := json.Indent(&buf, body, "", "  "); err == nil {
			body = buf.Bytes()
		}
		fmt.Println(string(body))
		return 0
	}

	var results []engine.Result
	if err := json.Unmarshal(body, &results); err != nil {
		fmt.Fprintf(os.Stderr, "解析响应失败: %v\n", err)
		return 1
	}
	printTable(results)
	return 0
}

// printTable 以对齐表格输出识别结果并给出汇总。
func printTable(results []engine.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	recognized := 0
	for _, r := range results {
		if r.Protocol != "unknown" {
			recognized++
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
	w.Flush()
	fmt.Printf("\n共 %d 条，识别成功 %d 条，未知 %d 条\n",
		len(results), recognized, len(results)-recognized)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
