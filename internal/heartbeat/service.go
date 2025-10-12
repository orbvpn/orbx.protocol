// internal/heartbeat/service.go

package heartbeat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/orbvpn/orbx.protocol/internal/config"
	"github.com/orbvpn/orbx.protocol/internal/wireguard"
)

type Service struct {
	config    *config.Config
	wgManager *wireguard.Manager
	ticker    *time.Ticker
	done      chan bool
}

type HeartbeatPayload struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

type MetricsInput struct {
	CurrentConnections int     `json:"currentConnections"`
	CPUUsage           float64 `json:"cpuUsage"`
	MemoryUsage        float64 `json:"memoryUsage"`
	LatencyMs          int     `json:"latencyMs"`
}

func NewService(cfg *config.Config, wgManager *wireguard.Manager) *Service {
	return &Service{
		config:    cfg,
		wgManager: wgManager,
		done:      make(chan bool),
	}
}

func (s *Service) Start() {
	// Send initial heartbeat
	s.sendHeartbeat()

	// Start ticker for periodic heartbeats
	s.ticker = time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.sendHeartbeat()
			case <-s.done:
				return
			}
		}
	}()
}

func (s *Service) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.done <- true

	// Send offline status
	s.sendStatus(false)
}

func (s *Service) sendHeartbeat() {
	// Update WireGuard stats
	s.wgManager.UpdatePeerStats()

	// Get system metrics
	metrics := s.getMetrics()

	// Send to OrbNet
	if err := s.sendMetrics(metrics); err != nil {
		log.Printf("❌ Heartbeat failed: %v", err)
	} else {
		log.Printf("💓 Heartbeat sent (peers: %d, CPU: %.1f%%, Mem: %.1f%%)",
			metrics.CurrentConnections, metrics.CPUUsage, metrics.MemoryUsage)
	}
}

func (s *Service) getMetrics() MetricsInput {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return MetricsInput{
		CurrentConnections: s.wgManager.GetPeerCount(),
		CPUUsage:           getCPUUsage(),
		MemoryUsage:        float64(m.Alloc) / float64(m.Sys) * 100,
		LatencyMs:          0, // Can be implemented with ping tests
	}
}

func (s *Service) sendMetrics(metrics MetricsInput) error {
	mutation := `
        mutation UpdateOrbXServerMetrics($serverId: ID!, $metrics: OrbXServerMetricsInput!) {
            updateOrbXServerMetrics(serverId: $serverId, metrics: $metrics) {
                id
                online
            }
        }
    `

	variables := map[string]interface{}{
		"serverId": s.config.OrbNet.ServerID,
		"metrics":  metrics,
	}

	return s.sendGraphQL(mutation, variables)
}

func (s *Service) sendStatus(online bool) error {
	mutation := `
        mutation UpdateOrbXServerStatus($serverId: ID!, $online: Boolean!) {
            updateOrbXServerStatus(serverId: $serverId, online: $online) {
                id
                online
            }
        }
    `

	variables := map[string]interface{}{
		"serverId": s.config.OrbNet.ServerID,
		"online":   online,
	}

	return s.sendGraphQL(mutation, variables)
}

func (s *Service) sendGraphQL(query string, variables map[string]interface{}) error {
	payload := HeartbeatPayload{
		Query:     query,
		Variables: variables,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", s.config.OrbNet.Endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.OrbNet.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func getCPUUsage() float64 {
	// Simple CPU usage estimation
	// In production, use a proper library like gopsutil
	return 0.0
}
