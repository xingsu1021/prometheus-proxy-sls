# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git for fetching Go modules
RUN apk add --no-cache git

# Copy go.mod file first
COPY go.mod ./

# Get the SLS SDK dependency
RUN GOPROXY=https://goproxy.cn,direct GOSUMDB=off go get github.com/aliyun/aliyun-log-go-sdk@latest

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o prometheus-remoteread-sls .

# Production stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/prometheus-remoteread-sls .

# Copy configuration
COPY config.yaml .

# Copy static files for web UI
COPY static/ ./static/

# Expose port
EXPOSE 8080

# Run as non-root user
RUN addgroup -S appgroup -g 1000 && \
    adduser -S appuser -u 1000 -G appgroup
USER 1000:1000

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/read || exit 1

# Run the application
ENTRYPOINT ["./prometheus-remoteread-sls"]
CMD ["-config", "config.yaml"]
