# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo \
    -o orbx-protocol \
    ./cmd/server

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 orbx && \
    adduser -D -u 1000 -G orbx orbx

WORKDIR /home/orbx

# Copy binary from builder
COPY --from=builder /app/orbx-protocol .

# Copy configuration template
COPY configs/config.yaml /etc/orbx/config.yaml

# Create directories for certs
RUN mkdir -p /etc/orbx/certs && \
    chown -R orbx:orbx /home/orbx /etc/orbx

# Switch to non-root user
USER orbx

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider https://localhost:8443/health || exit 1

# Run
CMD ["./orbx-protocol", "-config", "/etc/orbx/config.yaml"]