package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"prometheus-remoteread-sls/client"
	"prometheus-remoteread-sls/config"
	"prometheus-remoteread-sls/handler"
	"prometheus-remoteread-sls/logger"
)

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	// Initialize logger (default to debug level for startup, will re-init with config later)
	logger.Init("debug")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Re-initialize logger with config level
	logger.Init(cfg.Logging.Level)

	logger.Info("Starting Prometheus Remote Read SLS Proxy...")
	logger.Infof("SLS Endpoint: %s", cfg.SLS.Endpoint)
	logger.Infof("SLS Project: %s", cfg.SLS.Project)
	logger.Infof("SLS Logstore: %s", cfg.SLS.Logstore)
	logger.Infof("Server Address: %s", cfg.Server.GetAddress())
	logger.Infof("IdleTimeout: %v", cfg.Server.IdleTimeout)
	logger.Infof("Log Level: %s", cfg.Logging.Level)

	// Create SLS client
	slsClient, err := client.NewClient(&cfg.SLS)
	if err != nil {
		logger.Fatalf("Failed to create SLS client: %v", err)
	}
	defer slsClient.Close()

	// Set query concurrency
	slsClient.SetQueryConcurrency(cfg.RemoteRead.ConcurrentRequests)

	// Create handlers
	remoteReadHandler := handler.NewRemoteReadHandler(slsClient, cfg)
	healthHandler := handler.NewHealthHandler(slsClient, cfg)
	prometheusAPIHandler := handler.NewPrometheusAPIHandler(slsClient, cfg)

	// Create HTTP server with custom router and logging middleware
	srv := &http.Server{
		Addr:         cfg.Server.GetAddress(),
		Handler:      loggingMiddleware(createRouter(remoteReadHandler, healthHandler, prometheusAPIHandler)),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Configure TLS if enabled
	if cfg.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			logger.Fatalf("Failed to load TLS certificates: %v", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	// Start server in goroutine
	go func() {
		if cfg.TLS.Enabled {
			logger.Infof("Starting HTTPS server on %s", srv.Addr)
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("Failed to start HTTPS server: %v", err)
			}
		} else {
			logger.Infof("Starting HTTP server on %s", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("Failed to start HTTP server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown server
	if err := srv.Shutdown(ctx); err != nil {
		logger.Warnf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}

// createRouter creates the HTTP router with all handlers
func createRouter(remoteReadHandler http.Handler, healthHandler http.Handler, prometheusAPIHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		// Log all requests for debugging (only in debug mode)
		logger.Debugf("Request: Method=%s, Path=%s, RawPath=%s, RemoteAddr=%s",
			r.Method, path, r.URL.Path, r.RemoteAddr)

		// Health check endpoints (before static file serving)
		if strings.HasPrefix(path, "health") {
			logger.Debug("Routing to health handler")
			healthHandler.ServeHTTP(w, r)
			return
		}

		// Remote Read API endpoints - MUST check BEFORE general api/v1/ prefix
		// Use HasPrefix to handle query parameters
		if strings.HasPrefix(path, "api/v1/read") || path == "read" || strings.HasPrefix(path, "read") {
			logger.Debug("Routing to remote read handler")
			remoteReadHandler.ServeHTTP(w, r)
			return
		}

		// Prometheus API endpoints (query, label values, etc.)
		if strings.HasPrefix(path, "api/v1/") {
			logger.Debug("Routing to Prometheus API handler")
			prometheusAPIHandler.ServeHTTP(w, r)
			return
		}

		// Static file serving (web UI)
		if path == "" || path == "/" {
			logger.Debug("Serving index.html")
			// Serve the index.html
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "static/index.html")
			return
		}

		// Serve static files from ./static directory
		if strings.HasSuffix(path, ".html") ||
			strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".ico") ||
			strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".jpg") ||
			strings.HasSuffix(path, ".svg") {

			filePath := "static/" + path
			if _, err := os.Stat(filePath); err == nil {
				logger.Debugf("Serving static file: %s", filePath)
				// Determine content type
				contentType := getContentType(path)
				w.Header().Set("Content-Type", contentType)
				http.ServeFile(w, r, filePath)
				return
			}
			logger.Debugf("Static file not found: %s", filePath)
		}

		// 404 for everything else
		logger.Debugf("404 Not Found: %s", path)
		http.Error(w, "not found", http.StatusNotFound)
	})
}

// getContentType returns the content type for a file
func getContentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// loggingMiddleware logs all HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := newResponseWriter(w)

		logger.Debugf("<-- %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		logger.Debugf("--> %s %s - Status: %d, Duration: %v",
			r.Method, r.URL.Path, rw.statusCode, duration)
	})
}
