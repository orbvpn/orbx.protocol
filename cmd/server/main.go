// cmd/server/main.go
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/orbvpn/orbx-server/internal/auth"
	"github.com/orbvpn/orbx-server/internal/config"
	"github.com/orbvpn/orbx-server/internal/crypto"
	"github.com/orbvpn/orbx-server/internal/orbnet"
	"github.com/orbvpn/orbx-server/internal/protocol"
	"github.com/orbvpn/orbx-server/internal/tunnel"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "Path to configuration file")
	version    = "1.0.0"
	buildTime  = "unknown"
)

func main() {
	flag.Parse()

	// Print banner
	printBanner()

	// Load configuration
	log.Printf("Loading configuration from %s", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	log.Printf("Configuration loaded successfully")

	// Initialize components
	ctx := context.Background()

	// Initialize crypto (Kyber768 + Lattice)
	log.Println("Initializing post-quantum cryptography...")
	cryptoManager, err := crypto.NewManager(cfg.Crypto)
	if err != nil {
		log.Fatalf("Failed to initialize crypto: %v", err)
	}

	// Initialize JWT authenticator
	log.Println("Initializing JWT authentication...")
	jwtAuth := auth.NewJWTAuthenticator(cfg.JWT.Secret)

	// Initialize OrbNet client
	log.Println("Initializing OrbNet client...")
	orbnetClient := orbnet.NewClient(cfg.OrbNet.Endpoint, cfg.OrbNet.APIKey)

	// Initialize tunnel manager
	log.Println("Initializing tunnel manager...")
	tunnelManager := tunnel.NewManager(ctx, orbnetClient)

	// Initialize protocol router
	log.Println("Initializing protocol handlers...")
	protocolRouter := protocol.NewRouter(cfg, cryptoManager, tunnelManager)

	// Create TLS configuration
	tlsConfig, err := createTLSConfig(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		log.Fatalf("Failed to create TLS config: %v", err)
	}

	// Create HTTP server with protocol routing
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", handleHealth)

	// Metrics endpoint
	mux.HandleFunc("/metrics", handleMetrics(tunnelManager))

	// Protocol endpoints (Teams, Shaparak, DoH, HTTPS)
	mux.Handle("/teams/", auth.Middleware(jwtAuth, protocolRouter.HandleTeams()))
	mux.Handle("/shaparak/", auth.Middleware(jwtAuth, protocolRouter.HandleShaparak()))
	mux.Handle("/dns-query", auth.Middleware(jwtAuth, protocolRouter.HandleDoH()))
	mux.Handle("/", auth.Middleware(jwtAuth, protocolRouter.HandleHTTPS()))

	// Create server
	server := &http.Server{
		Addr:         cfg.Server.Host + ":" + cfg.Server.Port,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		log.Printf("🚀 OrbX Server starting on %s", server.Addr)
		log.Printf("📡 Protocols: Teams, Shaparak, DoH, HTTPS")
		log.Printf("🔐 Quantum-safe: %v", cfg.Crypto.QuantumSafe)

		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	// Stop tunnel manager
	tunnelManager.Stop()

	log.Println("Server exited")
}

func printBanner() {
	banner := `
    ╔═══════════════════════════════════════════╗
    ║          OrbX Server v%s              ║
    ║     Post-Quantum VPN Obfuscation         ║
    ╚═══════════════════════════════════════════╝
    `
	fmt.Printf(banner, version)
	fmt.Printf("    Build: %s\n\n", buildTime)
}

func createTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}, nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","version":"%s"}`, version)
}

func handleMetrics(tm *tunnel.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := tm.GetMetrics()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, `{
            "active_connections": %d,
            "total_bytes_sent": %d,
            "total_bytes_received": %d,
            "uptime_seconds": %d
        }`,
			metrics.ActiveConnections,
			metrics.TotalBytesSent,
			metrics.TotalBytesReceived,
			int(metrics.Uptime.Seconds()),
		)
	}
}
