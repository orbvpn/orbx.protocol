// cmd/server/main.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/orbvpn/orbx.protocol/internal/auth"
	"github.com/orbvpn/orbx.protocol/internal/config"
	"github.com/orbvpn/orbx.protocol/internal/crypto"
	"github.com/orbvpn/orbx.protocol/internal/heartbeat"
	"github.com/orbvpn/orbx.protocol/internal/orbnet"
	"github.com/orbvpn/orbx.protocol/internal/protocol"
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
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

	// Initialize protocol router (includes WireGuard)
	log.Println("Initializing protocol handlers...")
	protocolRouter, err := protocol.NewRouter(cfg, cryptoManager, tunnelManager)
	if err != nil {
		log.Fatalf("Failed to initialize protocol router: %v", err)
	}

	// Initialize heartbeat service
	if cfg.WireGuard.Enabled {
		log.Println("Initializing heartbeat service...")
		hb := heartbeat.NewService(cfg, protocolRouter.GetWireGuardHandler())
		hb.Start()
		defer hb.Stop()
	}

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

	// Protocol endpoints (Teams, Shaparak, DoH, HTTPS, Google)
	mux.Handle("/teams/", auth.Middleware(jwtAuth, protocolRouter.HandleTeams()))
	mux.Handle("/shaparak/", auth.Middleware(jwtAuth, protocolRouter.HandleShaparak()))
	mux.Handle("/dns-query", auth.Middleware(jwtAuth, protocolRouter.HandleDoH()))
	mux.Handle("/google/", auth.Middleware(jwtAuth, protocolRouter.HandleGoogle()))

	// Google Workspace endpoints
	mux.Handle("/drive/", auth.Middleware(jwtAuth, protocolRouter.HandleGoogle()))
	mux.Handle("/meet/", auth.Middleware(jwtAuth, protocolRouter.HandleGoogle()))
	mux.Handle("/calendar/", auth.Middleware(jwtAuth, protocolRouter.HandleGoogle()))

	// Video conferencing protocols
	mux.Handle("/zoom/", auth.Middleware(jwtAuth, protocolRouter.HandleZoom()))
	mux.Handle("/facetime/", auth.Middleware(jwtAuth, protocolRouter.HandleFaceTime()))

	// Russian services
	mux.Handle("/vk/", auth.Middleware(jwtAuth, protocolRouter.HandleVK()))
	mux.Handle("/yandex/", auth.Middleware(jwtAuth, protocolRouter.HandleYandex()))

	// Chinese services
	mux.Handle("/wechat/", auth.Middleware(jwtAuth, protocolRouter.HandleWeChat()))

	// WireGuard management endpoints (called by OrbNet)
	if cfg.WireGuard.Enabled {
		mux.HandleFunc("/wireguard/add-peer", handleWireGuardAddPeer(protocolRouter))
		mux.HandleFunc("/wireguard/remove-peer", handleWireGuardRemovePeer(protocolRouter))
		mux.HandleFunc("/wireguard/status", handleWireGuardServerStatus(protocolRouter))
	}

	// Fallback handler (HTTPS)
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

		// Build protocol list
		protocols := "WireGuard, Teams, Google, Shaparak, DoH, HTTPS, Zoom, FaceTime, VK, Yandex, WeChat"
		if cfg.WireGuard.Enabled {
			protocols = "WireGuard, " + protocols
		}
		log.Printf("📡 Protocols: %s", protocols)
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

	// Stop protocol router (closes WireGuard)
	if err := protocolRouter.Close(); err != nil {
		log.Printf("Error closing protocol router: %v", err)
	}

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

// WireGuard management handlers (called by OrbNet backend via API key auth)
func handleWireGuardAddPeer(router *protocol.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request from OrbNet
		var req struct {
			UserUUID   string `json:"userUuid"`
			PublicKey  string `json:"publicKey"`
			AllowedIPs string `json:"allowedIPs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Add peer to WireGuard
		wgMgr := router.GetWireGuardHandler()
		if wgMgr == nil {
			http.Error(w, "WireGuard not enabled", http.StatusServiceUnavailable)
			return
		}

		ip, err := wgMgr.AddPeer(req.UserUUID, req.PublicKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to add peer: %v", err), http.StatusInternalServerError)
			return
		}

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"message":  "Peer added successfully",
			"userUuid": req.UserUUID,
			"ip":       ip.String(),
		})
	}
}

func handleWireGuardRemovePeer(router *protocol.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserUUID string `json:"userUuid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		wgMgr := router.GetWireGuardHandler()
		if wgMgr == nil {
			http.Error(w, "WireGuard not enabled", http.StatusServiceUnavailable)
			return
		}

		if err := wgMgr.RemovePeer(req.UserUUID); err != nil {
			http.Error(w, fmt.Sprintf("Failed to remove peer: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"message":  "Peer removed successfully",
			"userUuid": req.UserUUID,
		})
	}
}

func handleWireGuardServerStatus(router *protocol.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wgMgr := router.GetWireGuardHandler()
		if wgMgr == nil {
			http.Error(w, "WireGuard not enabled", http.StatusServiceUnavailable)
			return
		}

		// Update stats before returning
		wgMgr.UpdatePeerStats()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"publicKey": wgMgr.GetPublicKey(),
			"peerCount": wgMgr.GetPeerCount(),
		})
	}
}
