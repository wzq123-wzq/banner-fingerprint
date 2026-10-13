# Banner 指纹识别系统

基于 Golang 的 **client + server** 架构 Banner 指纹识别系统：接收网络扫描原始数据（ip、port、banner），识别对应的协议、软件与版本信息。整套系统以 Docker Compose 一键启动，按生产级标准部署。

## 功能特性

- **批量识别**：`POST /fingerprint` 一次识别一批扫描数据，结果与输入顺序严格一致
- **识别深度**：协议 → 产品/软件 → 版本 → 操作系统提示（os_hint）→ 置信度（0~1）
- **绝不崩溃**：任何输入（畸形 JSON、二进制字节流、空 banner）都无法让服务出错——认不出来统一返回 `protocol: "unknown"`，置信度 0
- **规则与代码解耦**：全部指纹规则位于 YAML 文件，修改/新增规则**无需重编译**，`GET /rules` 可查看当前加载的规则
- **生产级部署**：多阶段构建 + scratch 镜像、非 root 运行、只读根文件系统、真实健康检测、优雅停机、结构化日志

## 快速开始

### Docker Compose 一键启动（推荐）

```bash
docker compose up --build
```

启动后：

```bash
# 查看客户端识别结果（一次性任务，跑完即退出）
docker compose logs client

# 手动调用 API
curl -s http://localhost:8080/health
curl -s -X POST http://localhost:8080/fingerprint \
     -H 'Content-Type: application/json' \
     --data-binary @samples/banners.json
```

### 本地运行（无 Docker）

```bash
go run ./server                  # 服务端，监听 :8080
go run ./client -file samples/banners.json   # 客户端，输出表格结果
go run ./client -file samples/banners.json -json  # JSON 输出
```

## 架构设计

```
扫描原始数据(JSON 文件)                Docker Compose 单一网络 fp-net
        │                                        │
        ▼                                        ▼
┌──────────────────┐  POST /fingerprint  ┌──────────────────┐
│  client (Go CLI) │ ──────────────────► │  server (Go API) │
│  一次性容器       │  http://server:8080 │  常驻容器         │
│  表格/JSON 输出   │ ◄────────────────── │  批量识别/健康检查  │
└──────────────────┘    JSON 结果         └────────┬─────────┘
                                                   │
                                     ┌─────────────▼─────────────┐
                                     │ 规则引擎（与代码完全解耦）  │
                                     │ YAML 规则: embed 内置      │
                                     │ + RULES_DIR 运行时挂载覆盖 │
                                     └───────────────────────────┘
```

- **client**：独立 CLI 程序，读取本地 JSON 文件、发送到 server、以表格（或 `-json` 原始 JSON）展示结果；连接失败自动重试
- **server**：无状态 HTTP API，规则引擎并发批量识别；`-healthcheck` 子命令可自检（scratch 镜像无 shell/curl 也能用于 HEALTHCHECK）
- **规则引擎**：不含任何硬编码指纹逻辑，全部来自 YAML 规则文件（内嵌编译 + 外部目录覆盖）

## API 文档

### `POST /fingerprint` — 批量识别

请求体支持裸数组或包装对象两种形态：

```json
[
  {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip": "1.2.3.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}
]
```

响应：

```json
[
  {"ip": "1.2.3.4", "port": 22, "protocol": "SSH", "product": "OpenSSH", "version": "8.9p1", "os_hint": "Ubuntu", "confidence": 0.95},
  {"ip": "1.2.3.5", "port": 80, "protocol": "HTTP", "product": "nginx", "version": "1.24.0", "os_hint": "", "confidence": 0.9}
]
```

语义约定：

| 项 | 说明 |
|---|---|
| 结果字段 | `ip`/`port` 原样回显；`protocol`/`product`/`version`/`os_hint`/`confidence`(0~1) |
| unknown 语义 | 识别不出时 `protocol:"unknown"`，其余字段空串，`confidence:0`——**不报错** |
| 脏数据 | 单条字段类型不合法（如 banner 是数字）按空值处理为 unknown，**不影响同批其他条目** |
| 错误响应 | 仅整包非法时返回 `4xx` + `{"error":"..."}`（非法 JSON、超 16 MiB、超 20 万条） |
| 限流保护 | 请求体 ≤ 16 MiB，单次 ≤ 200,000 条 |

### `GET /health` — 健康检查

```json
{"status": "ok", "uptime_seconds": 123}
```

供 Docker HEALTHCHECK（每 5s 探测）与运维探活使用。

### `GET /rules` — 已加载规则摘要

返回规则来源（`embedded:` / `external:`）与全部协议、产品、兜底端口，自证「规则与代码解耦」：修改 `server/rules/*.yaml` 后重启容器即可生效，无需改代码、无需重编译。

## 识别能力与置信度语义

| 协议 | 产品/软件 | 示例 banner | 输出 |
|---|---|---|---|
| SSH | OpenSSH、dropbear | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` | 版本 `8.9p1`，os_hint `Ubuntu`，0.95 |
| HTTP | nginx、Apache、Jetty、Microsoft-IIS、Tomcat(Apache-Coyote)、OpenResty、lighttpd、Caddy、Gunicorn、Elasticsearch | `Server: nginx/1.18.0 (Ubuntu)` | 版本 + `(Ubuntu)`→os_hint，0.9 |
| MySQL | MySQL、MariaDB（识别 `5.5.5-x-MariaDB` 伪装） | 二进制握手 `J\0\0\0\n8.0.32\0` | 版本 `8.0.32`，0.9 |
| Redis | Redis | `+PONG` / `-ERR ...` / `-NOAUTH ...`；INFO 输出可提取 `redis_version:` | 无版本 0.7，有版本 0.95 |
| FTP | ProFTPD、vsFTPd、Pure-FTPd、Microsoft FTP、FileZilla、Serv-U | `220 ProFTPD 1.3.7 Server` | 0.9 |
| SMTP | Postfix、Exim、Sendmail、Microsoft ESMTP | `220 mail ESMTP Postfix 3.5.8` | 0.9 |
| PostgreSQL | PostgreSQL | `EFATAL: password authentication failed...` | 0.7 |
| TLS | （记录层检测） | `\x16\x03\x01...` ClientHello | protocol `TLS`，0.6 |

置信度语义：产品+版本命中 = 规则 confidence（0.85~0.95）；产品命中无版本 = no_version_confidence（0.65~0.75）；仅协议命中 = 0.6；banner 完全无信息时按端口兜底 = 0.3~0.35；识别不出 = 0。

## 规则扩展指南（规则与代码解耦）

规则位于 [server/rules/protocols.yaml](server/rules/protocols.yaml)，顶层为协议列表。**新增一个协议**只需追加一段 YAML：

```yaml
  - name: MQTT
    priority: 60
    matcher: '^\x20'                    # 协议级判定正则（Go RE2 语法）
    protocol_confidence: 0.6
    ports: [1883]
    port_hint_confidence: 0.35
    products:
      - product: EMQX
        regex: '(?i)EMQX[ /]?(?P<version>\d+\.\d+(?:\.\d+)?)'  # (?P<version>) 命名捕获
        confidence: 0.9
        no_version_confidence: 0.7
```

字段含义见规则文件头部注释。两种生效方式：

1. **修改内置规则**：改 `server/rules/protocols.yaml` → `docker compose up --build`（重新打包镜像）
2. **运行时覆盖（推荐，零重编译）**：compose 已把 `./server/rules` 以只读方式挂载到容器 `/rules`（`RULES_DIR` 环境变量）。修改/新增 YAML 后只需 `docker compose restart server`。同名协议整体覆盖内置规则，新协议直接追加；外部规则格式错误只跳过该文件，不影响内置规则。

## 生产级部署说明

| 生产要求 | 实现方式 |
|---|---|
| 容器间访问收敛 | client 仅通过 compose 网络 DNS `http://server:8080` 访问 server，不依赖宿主机 IP/端口；单一显式网络 `fp-net` |
| 真实健康检测 | server `HEALTHCHECK` 每 5s 真实探测 `/health`（二进制 `-healthcheck` 自检，scratch 镜像无 shell 也能用）；client `depends_on: condition: service_healthy`，无 sleep 占位 |
| 编译打包 | 多阶段构建 `golang:1.23-alpine` → `scratch`；构建阶段内跑 `go vet` + `go test`（测试不过则镜像构建失败）；依赖 vendor 化、构建零外网；`CGO_ENABLED=0` 静态编译 + `-trimpath -ldflags="-s -w"` |
| 权限收紧 | `USER 65532` 非 root；只读根文件系统（`read_only`）；`cap_drop: ALL`；`no-new-privileges`；scratch 无 shell 无多余工具 |
| 服务韧性 | SIGTERM 优雅停机（10s 等待在途请求）；`recover` 中间件兜底 panic；请求体/条数限流；读/写超时；结构化 JSON 日志 |
| 规则解耦 | 见上节 |

## 测试

```bash
go vet ./... && go test -race ./...
```

测试覆盖：

- **引擎**：题目给定 20 条自测数据逐条断言（含示例要求的全部输出，期望值与 [samples/expected.json](samples/expected.json) 一致）；MariaDB/dropbear/Tomcat/SMTP/PostgreSQL 等扩展形态；空 banner 端口兜底；批量识别保序；外部规则覆盖生效；坏外部规则被忽略
- **API**：五类协议批量识别、包装请求体、unknown 不报错、畸形 JSON→400、脏条目不影响整批、空数组、/health、/rules
- **CI**：GitHub Actions 执行 vet + 竞态检测测试 + 双镜像构建（[.github/workflows/ci.yml](.github/workflows/ci.yml)）

## 目录结构

```
├── docker-compose.yml        # 一键启动编排（健康依赖、权限收紧、网络收敛）
├── server/
│   ├── Dockerfile            # 多阶段构建 → scratch
│   ├── main.go               # 入口：API 服务 / -healthcheck 自检模式
│   ├── api.go                # /fingerprint /health /rules + 中间件
│   ├── api_test.go
│   ├── engine/
│   │   ├── engine.go         # 规则驱动识别引擎（无硬编码指纹）
│   │   └── engine_test.go
│   └── rules/
│       ├── rules.go          # go:embed 内嵌规则
│       └── protocols.yaml    # ★ 指纹规则库（与代码解耦）
├── client/
│   ├── Dockerfile
│   └── main.go               # CLI：读文件 → 发送 → 表格/JSON 展示
└── samples/
    ├── banners.json          # 自测输入（20 条原始扫描数据）
    └── expected.json         # 自测期望输出（引擎单测断言依据）
```

## License

[MIT](LICENSE)
