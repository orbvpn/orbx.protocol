// internal/orbnet/client.go
package orbnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Client handles communication with OrbNet GraphQL API
type Client struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new OrbNet client
func NewClient(endpoint, apiKey string) *Client {
	return &Client{
		endpoint: endpoint,
		apiKey:   apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GraphQL request/response structures
type graphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphQLError  `json:"errors,omitempty"`
}

type graphQLError struct {
	Message string   `json:"message"`
	Path    []string `json:"path,omitempty"`
}

// RecordUsage sends usage metrics to OrbNet
func (c *Client) RecordUsage(ctx context.Context, metrics *models.UsageMetrics) error {
	mutation := `
        mutation RecordOrbXUsage($input: OrbXUsageInput!) {
            recordOrbXUsage(input: $input) {
                success
                message
            }
        }
    `

	variables := map[string]interface{}{
		"input": map[string]interface{}{
			"userId":         metrics.UserID,
			"serverId":       metrics.ServerID,
			"sessionId":      metrics.SessionID,
			"bytesSent":      metrics.BytesSent,
			"bytesReceived":  metrics.BytesRecv,
			"duration":       int(metrics.Duration.Seconds()),
			"protocol":       metrics.Protocol,
			"disconnectedAt": metrics.DisconnectAt.Format(time.RFC3339),
		},
	}

	var result struct {
		RecordOrbXUsage struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
		} `json:"recordOrbXUsage"`
	}

	if err := c.query(ctx, mutation, variables, &result); err != nil {
		return fmt.Errorf("failed to record usage: %w", err)
	}

	if !result.RecordOrbXUsage.Success {
		return fmt.Errorf("usage recording failed: %s", result.RecordOrbXUsage.Message)
	}

	return nil
}

// GetServerConfig retrieves server configuration from OrbNet
func (c *Client) GetServerConfig(ctx context.Context, serverID int64) (*models.ServerConfig, error) {
	query := `
        query GetOrbXConfig($serverId: ID!) {
            orbxConfig(serverId: $serverId) {
                serverId
                endpoint
                port
                publicKey
                protocols
                tlsFingerprint
                quantumSafe
                region
            }
        }
    `

	variables := map[string]interface{}{
		"serverId": serverID,
	}

	var result struct {
		OrbXConfig models.ServerConfig `json:"orbxConfig"`
	}

	if err := c.query(ctx, query, variables, &result); err != nil {
		return nil, fmt.Errorf("failed to get server config: %w", err)
	}

	return &result.OrbXConfig, nil
}

// ValidateUser checks if a user is authorized to use OrbX
func (c *Client) ValidateUser(ctx context.Context, userID int) (bool, error) {
	query := `
        query GetUser($id: Int!) {
            getUserById(id: $id) {
                id
                email
                userSubscription {
                    isActive
                    expirationDate
                }
            }
        }
    `

	variables := map[string]interface{}{
		"id": userID,
	}

	var result struct {
		GetUserById struct {
			ID               int    `json:"id"`
			Email            string `json:"email"`
			UserSubscription struct {
				IsActive       bool   `json:"isActive"`
				ExpirationDate string `json:"expirationDate"`
			} `json:"userSubscription"`
		} `json:"getUserById"`
	}

	if err := c.query(ctx, query, variables, &result); err != nil {
		return false, fmt.Errorf("failed to validate user: %w", err)
	}

	return result.GetUserById.UserSubscription.IsActive, nil
}

// query executes a GraphQL query
func (c *Client) query(ctx context.Context, query string, variables map[string]interface{}, result interface{}) error {
	reqBody := graphQLRequest{
		Query:     query,
		Variables: variables,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var gqlResp graphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	if err := json.Unmarshal(gqlResp.Data, result); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// Heartbeat sends a heartbeat to OrbNet to update server status
func (c *Client) Heartbeat(ctx context.Context, serverID int64, metrics *ServerMetrics) error {
	mutation := `
        mutation UpdateServerMetrics($serverId: ID!, $metrics: ServerMetricsInput!) {
            updateOrbXServerMetrics(serverId: $serverId, metrics: $metrics) {
                success
            }
        }
    `

	variables := map[string]interface{}{
		"serverId": serverID,
		"metrics": map[string]interface{}{
			"activeConnections": metrics.ActiveConnections,
			"cpuUsage":          metrics.CPUUsage,
			"memoryUsage":       metrics.MemoryUsage,
			"latencyMs":         metrics.LatencyMs,
		},
	}

	var result struct {
		UpdateOrbXServerMetrics struct {
			Success bool `json:"success"`
		} `json:"updateOrbXServerMetrics"`
	}

	return c.query(ctx, mutation, variables, &result)
}

// ServerMetrics represents server health metrics
type ServerMetrics struct {
	ActiveConnections int     `json:"activeConnections"`
	CPUUsage          float64 `json:"cpuUsage"`
	MemoryUsage       float64 `json:"memoryUsage"`
	LatencyMs         int     `json:"latencyMs"`
}
