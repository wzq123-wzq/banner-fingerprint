// Package rules 内嵌 Banner 指纹识别规则库。
//
// 规则与程序代码完全解耦：
//   - 本目录下的 *.yaml 通过 go:embed 编译进二进制，保证镜像自包含、开箱即用；
//   - 运行时可通过 RULES_DIR 环境变量指向外部规则目录，同名协议整体覆盖、
//     新协议直接追加，均无需重新编译（详见 README「规则扩展」章节）。
package rules

import "embed"

// FS 内嵌规则文件系统，仅包含 *.yaml 规则文件。
//
//go:embed *.yaml
var FS embed.FS
