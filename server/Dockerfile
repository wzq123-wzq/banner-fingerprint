# =============================================================================
# 识别服务端镜像 — 多阶段构建: golang:1.23-alpine 编译 → scratch 运行
#   - 构建阶段内先跑 go vet + go test，测试不过则镜像构建失败（质量门禁）
#   - 依赖已 vendor 进仓库，构建过程零外网下载
#   - 静态编译（CGO_ENABLED=0）+ trimpath + 剥离符号，产物可运行于 scratch
#   - 运行镜像为 scratch：无 shell、无包管理器、无任何多余文件，攻击面最小；
#     以非 root 用户 65532 运行
# =============================================================================

# ---- 构建阶段 ----
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY server/ ./server/
COPY client/ ./client/
RUN go vet -mod=vendor ./server/... ./client/... \
 && go test -mod=vendor ./server/... ./client/...
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath \
    -ldflags="-s -w" -o /out/server ./server

# ---- 运行阶段 ----
FROM scratch
COPY --from=build /out/server /app/server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/server"]
