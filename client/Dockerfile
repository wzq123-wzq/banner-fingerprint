# =============================================================================
# 识别客户端镜像 — 与 server 相同的多阶段构建与加固策略
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
    -ldflags="-s -w" -o /out/client ./client

# ---- 运行阶段 ----
FROM scratch
COPY --from=build /out/client /app/client
USER 65532:65532
ENTRYPOINT ["/app/client"]
