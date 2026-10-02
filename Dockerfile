FROM golang:alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" -o /out/dockwall ./cmd/dockwall

FROM alpine:latest
RUN apk add --no-cache iptables
COPY --from=builder /out/dockwall /usr/local/bin/dockwall
ENTRYPOINT ["/usr/local/bin/dockwall"]
CMD ["-config", "/etc/dockwall/config.yaml"]
