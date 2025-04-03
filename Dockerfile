# syntax=docker/dockerfile:1.7

############################
# Builder
############################
FROM golang:1.25-alpine AS build
WORKDIR /src

# Better cache hits
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build vpnless-caddy
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/vpnless-caddy ./cmd/vpnless-caddy

############################
# Runtime (Caddy-style)
############################
FROM caddy:2.11.2-alpine

# Optional metadata
LABEL org.opencontainers.image.source="https://github.com/vpnless/vpnless"

# Replace stock caddy binary with vpnless-caddy
COPY --from=build /out/vpnless-caddy /usr/bin/caddy

# Keep same runtime UX as official Caddy image
EXPOSE 80 443 443/udp
VOLUME ["/data", "/config", "/etc/caddy"]

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]