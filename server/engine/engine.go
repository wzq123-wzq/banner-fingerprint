// Package engine 实现 Banner 指纹识别引擎。
//
// 引擎本身不含任何硬编码的指纹逻辑：所有协议/产品/版本/置信度规则均来自
// YAML 规则文件（内嵌 + 可选外部目录）。引擎保证对任意输入（空 banner、
// 二进制字节流、畸形数据）都不会 panic 或返回错误——识别不出时返回
// protocol="unknown" 的结果。
package engine

import (
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"
)

// Target 是扫描器产出的一条原始数据。
type Target struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result 是单条识别结果。无法识别时 Protocol 为 "unknown"、其余字段为空串、
// Confidence 为 0。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// ProtocolRule 一个协议的识别规则（对应 YAML 中 protocols 的每一项）。
type ProtocolRule struct {
	Name                string        `yaml:"name"`
	Priority            int           `yaml:"priority"`
	Matcher             string        `yaml:"matcher"`
	ProtocolConfidence  float64       `yaml:"protocol_confidence"`
	DefaultProduct      string        `yaml:"default_product"`
	VersionRegex        string        `yaml:"version_regex"`
	OSHintRegex         string        `yaml:"os_hint_regex"`
	Confidence          float64       `yaml:"confidence"`
	NoVersionConfidence float64       `yaml:"no_version_confidence"`
	Ports               []int         `yaml:"ports"`
	PortHintConfidence  float64       `yaml:"port_hint_confidence"`
	Products            []ProductRule `yaml:"products"`

	matcher      *regexp.Regexp
	versionRe    *regexp.Regexp
	osHintRe     *regexp.Regexp
	productRules []*compiledProduct
}

// ProductRule 单个产品/软件的匹配规则。
type ProductRule struct {
	Product             string  `yaml:"product"`
	Priority            int     `yaml:"priority"`
	Regex               string  `yaml:"regex"`
	VersionRegex        string  `yaml:"version_regex"`
	OSHintRegex         string  `yaml:"os_hint_regex"`
	Confidence          float64 `yaml:"confidence"`
	NoVersionConfidence float64 `yaml:"no_version_confidence"`
}

// compiledProduct 编译后的产品规则。
type compiledProduct struct {
	rule      ProductRule
	regex     *regexp.Regexp
	versionRe *regexp.Regexp
	osHintRe  *regexp.Regexp
}

// RulesFile 规则文件的顶层结构。
type RulesFile struct {
	Version   int            `yaml:"version"`
	Protocols []ProtocolRule `yaml:"protocols"`
}

// RulesInfo 描述当前已加载的规则（供 GET /rules 接口自证“规则与代码解耦”）。
type RulesInfo struct {
	Version   int            `json:"version"`
	Sources   []string       `json:"sources"`
	Protocols []ProtocolInfo `json:"protocols"`
}

// ProtocolInfo 单个协议在 RulesInfo 中的摘要。
type ProtocolInfo struct {
	Name     string   `json:"name"`
	Products []string `json:"products"`
	Ports    []int    `json:"ports,omitempty"`
}

// Engine 由规则文件编译而成，并发安全。
type Engine struct {
	mu        sync.RWMutex
	protocols []*ProtocolRule
	sources   []string
}

// Load 从内嵌规则与可选的外部规则目录构建引擎。
//
// externalDir 非空时，其中的 *.yaml 按文件名排序加载：与内嵌规则同名的协议
// 整体覆盖（便于调优），新协议直接追加，均无需重编译程序。内嵌规则错误视为
// 开发期缺陷直接失败；外部规则错误只告警跳过该文件，不影响内嵌规则可用。
func Load(embedded fs.FS, externalDir string) (*Engine, error) {
	e := &Engine{}
	if err := e.loadFS(embedded, "embedded"); err != nil {
		return nil, err
	}
	if externalDir != "" {
		e.loadDir(externalDir)
	}
	e.sort()
	return e, nil
}

func (e *Engine) loadFS(fsys fs.FS, label string) error {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return err
	}
	for _, n := range names {
		data, err := fs.ReadFile(fsys, n)
		if err != nil {
			return err
		}
		if err := e.addFile(label+":"+n, data, true); err != nil {
			return fmt.Errorf("加载内嵌规则 %s: %w", n, err)
		}
	}
	return nil
}

func (e *Engine) loadDir(dir string) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return
	}
	sort.Strings(matches)
	for _, f := range matches {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取外部规则 %s 失败: %v\n", f, err)
			continue
		}
		if err := e.addFile("external:"+filepath.Base(f), data, false); err != nil {
			fmt.Fprintf(os.Stderr, "忽略无效外部规则 %s: %v\n", f, err)
		}
	}
}

// addFile 解析并编译一个规则文件；strict 决定错误是否致命。
func (e *Engine) addFile(label string, data []byte, strict bool) error {
	var f RulesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return err
	}
	if f.Version == 0 {
		f.Version = 1
	}
	for i := range f.Protocols {
		p := &f.Protocols[i]
		if err := p.compile(); err != nil {
			return fmt.Errorf("协议 %s: %w", p.Name, err)
		}
		// 同名协议：后加载者（外部规则）整体覆盖先加载者（内嵌规则）
		replaced := false
		for j, exist := range e.protocols {
			if exist.Name == p.Name {
				e.protocols[j] = p
				replaced = true
				break
			}
		}
		if !replaced {
			e.protocols = append(e.protocols, p)
		}
	}
	e.sources = append(e.sources, label)
	return nil
}

func (p *ProtocolRule) compile() error {
	var err error
	if p.Matcher != "" {
		if p.matcher, err = regexp.Compile(p.Matcher); err != nil {
			return fmt.Errorf("matcher: %w", err)
		}
	}
	if p.VersionRegex != "" {
		if p.versionRe, err = regexp.Compile(p.VersionRegex); err != nil {
			return fmt.Errorf("version_regex: %w", err)
		}
	}
	if p.OSHintRegex != "" {
		if p.osHintRe, err = regexp.Compile(p.OSHintRegex); err != nil {
			return fmt.Errorf("os_hint_regex: %w", err)
		}
	}
	for i := range p.Products {
		pr := &p.Products[i]
		if pr.Regex == "" {
			return fmt.Errorf("产品 %s 缺少 regex", pr.Product)
		}
		cp := &compiledProduct{rule: *pr}
		if cp.regex, err = regexp.Compile(pr.Regex); err != nil {
			return fmt.Errorf("产品 %s regex: %w", pr.Product, err)
		}
		if pr.VersionRegex != "" {
			if cp.versionRe, err = regexp.Compile(pr.VersionRegex); err != nil {
				return fmt.Errorf("产品 %s version_regex: %w", pr.Product, err)
			}
		}
		if pr.OSHintRegex != "" {
			if cp.osHintRe, err = regexp.Compile(pr.OSHintRegex); err != nil {
				return fmt.Errorf("产品 %s os_hint_regex: %w", pr.Product, err)
			}
		}
		p.productRules = append(p.productRules, cp)
	}
	// 产品按优先级降序尝试
	sort.SliceStable(p.productRules, func(a, b int) bool {
		return p.productRules[a].rule.Priority > p.productRules[b].rule.Priority
	})
	return nil
}

func (e *Engine) sort() {
	sort.SliceStable(e.protocols, func(a, b int) bool {
		return e.protocols[a].Priority > e.protocols[b].Priority
	})
}

// Identify 识别单个目标。此方法不会 panic、不会返回错误：规则未命中时
// 返回 protocol="unknown"、confidence=0 的结果。
func (e *Engine) Identify(t Target) Result {
	res := Result{IP: t.IP, Port: t.Port, Protocol: "unknown"}

	e.mu.RLock()
	defer e.mu.RUnlock()

	banner := t.Banner

	// 1) banner 驱动的协议判定（按协议优先级）
	for _, p := range e.protocols {
		if p.matcher == nil || !p.matcher.MatchString(banner) {
			continue
		}
		res.Protocol = p.Name

		// 1a) 产品级指纹
		for _, pr := range p.productRules {
			if !pr.regex.MatchString(banner) {
				continue
			}
			res.Product = pr.rule.Product
			res.Version = p.productVersion(pr, banner)
			res.OSHint = p.productOSHint(pr, banner)
			res.Confidence = clamp(confidenceFor(pr.rule, res.Version != ""))
			return res
		}

		// 1b) 默认产品（“协议名即产品名”类）
		if p.DefaultProduct != "" {
			res.Product = p.DefaultProduct
			res.Version = p.versionFrom(banner)
			res.OSHint = captureFrom(banner, p.osHintRe)
			if res.Version != "" {
				res.Confidence = clamp(orDefault(p.Confidence, 0.9))
			} else {
				res.Confidence = clamp(orDefault(p.NoVersionConfidence, 0.7))
			}
			return res
		}

		// 1c) 协议命中但产品无法细分
		res.Confidence = clamp(orDefault(p.ProtocolConfidence, 0.6))
		return res
	}

	// 2) banner 完全无信息时的端口兜底（低置信度）
	for _, p := range e.protocols {
		for _, port := range p.Ports {
			if port == t.Port {
				res.Protocol = p.Name
				res.Product = p.DefaultProduct
				res.Confidence = clamp(orDefault(p.PortHintConfidence, 0.3))
				return res
			}
		}
	}
	return res
}

// IdentifyBatch 并发识别一批目标，结果与输入顺序严格一致。
func (e *Engine) IdentifyBatch(targets []Target, workers int) []Result {
	results := make([]Result, len(targets))
	if len(targets) == 0 {
		return results
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	ch := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range ch {
				results[idx] = e.Identify(targets[idx])
			}
		}()
	}
	for i := range targets {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return results
}

// RulesInfo 返回当前已加载规则的摘要。
func (e *Engine) RulesInfo() RulesInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	info := RulesInfo{Version: 1, Sources: append([]string(nil), e.sources...)}
	for _, p := range e.protocols {
		pi := ProtocolInfo{Name: p.Name, Ports: p.Ports}
		for _, pr := range p.productRules {
			pi.Products = append(pi.Products, pr.rule.Product)
		}
		if p.DefaultProduct != "" {
			pi.Products = append(pi.Products, p.DefaultProduct+"*")
		}
		info.Protocols = append(info.Protocols, pi)
	}
	return info
}

// productVersion 依次尝试：产品 version_regex → 产品 regex 的 version 捕获组
// → 协议 version_regex → 协议 matcher 的 version 捕获组。
func (p *ProtocolRule) productVersion(pr *compiledProduct, banner string) string {
	if v := captureFrom(banner, pr.versionRe); v != "" {
		return v
	}
	if v := captureFrom(banner, pr.regex); v != "" {
		return v
	}
	return p.versionFrom(banner)
}

func (p *ProtocolRule) versionFrom(banner string) string {
	if v := captureFrom(banner, p.versionRe); v != "" {
		return v
	}
	return captureFrom(banner, p.matcher)
}

// productOSHint 依次尝试：产品 os_hint_regex → 协议 os_hint_regex。
func (p *ProtocolRule) productOSHint(pr *compiledProduct, banner string) string {
	if v := captureFrom(banner, pr.osHintRe); v != "" {
		return v
	}
	return captureFrom(banner, p.osHintRe)
}

// captureFrom 从正则匹配结果中取值：优先命名组 version/os，其次第一个捕获组。
func captureFrom(banner string, re *regexp.Regexp) string {
	if re == nil || banner == "" {
		return ""
	}
	m := re.FindStringSubmatch(banner)
	if m == nil {
		return ""
	}
	for i, name := range re.SubexpNames() {
		if (name == "version" || name == "os") && i < len(m) && m[i] != "" {
			return m[i]
		}
	}
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// confidenceFor 计算产品置信度：带版本用 confidence，否则用
// no_version_confidence（缺省为 confidence-0.2）。
func confidenceFor(r ProductRule, hasVersion bool) float64 {
	if hasVersion {
		return orDefault(r.Confidence, 0.9)
	}
	return orDefault(r.NoVersionConfidence, orDefault(r.Confidence, 0.9)-0.2)
}

func orDefault(v, def float64) float64 {
	if v <= 0 {
		return def
	}
	return v
}

func clamp(v float64) float64 {
	return math.Max(0, math.Min(1, v))
}
