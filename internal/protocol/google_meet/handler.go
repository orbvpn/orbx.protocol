// internal/protocol/google_meet.go
package protocol

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GoogleMeetHandler handles traffic disguised as Google Meet protocol
type GoogleMeetHandler struct {
	BaseHandler
}

// GoogleMeetMessage mimics Google Meet WebRTC signaling
type GoogleMeetMessage struct {
	Type      string                 `json:"type"`      // "offer", "answer", "candidate"
	SessionID string                 `json:"sessionId"` // Meet session ID
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"` // Actual VPN data hidden here
	SDP       string                 `json:"sdp,omitempty"`
	Candidate string                 `json:"candidate,omitempty"`
}

// NewGoogleMeetHandler creates a new Google Meet protocol handler
func NewGoogleMeetHandler() *GoogleMeetHandler {
	return &GoogleMeetHandler{
		BaseHandler: BaseHandler{
			Protocol: "google-meet",
		},
	}
}

// Handle processes Google Meet protocol requests
func (h *GoogleMeetHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// Validate Google Meet headers
	if !h.validateMeetHeaders(r) {
		http.Error(w, "Invalid Google Meet request", http.StatusBadRequest)
		return
	}

	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse as Google Meet message
	var meetMsg GoogleMeetMessage
	if err := json.Unmarshal(body, &meetMsg); err != nil {
		http.Error(w, "Invalid Google Meet message", http.StatusBadRequest)
		return
	}

	// Extract actual VPN data from the hidden data field
	vpnData, err := h.extractVPNData(&meetMsg)
	if err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Process through tunnel (actual VPN logic)
	response, err := h.ProcessTunnel(r.Context(), vpnData)
	if err != nil {
		http.Error(w, "Tunnel error", http.StatusInternalServerError)
		return
	}

	// Wrap response in Google Meet format
	meetResponse := h.createMeetResponse(&meetMsg, response)

	// Send response with Google Meet headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "https://meet.google.com")
	w.Header().Set("X-Meet-Session", meetMsg.SessionID)
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(meetResponse)
}

// validateMeetHeaders checks if request has valid Google Meet headers
func (h *GoogleMeetHandler) validateMeetHeaders(r *http.Request) bool {
	// Google Meet uses specific headers for WebRTC signaling
	requiredHeaders := map[string]bool{
		"Content-Type": false,
		"Origin":       false,
		"User-Agent":   false,
	}

	// Check Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" || contentType == "application/json; charset=utf-8" {
		requiredHeaders["Content-Type"] = true
	}

	// Check Origin (should be from meet.google.com or similar)
	origin := r.Header.Get("Origin")
	if origin != "" {
		requiredHeaders["Origin"] = true
	}

	// Check User-Agent (should look like a browser)
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		requiredHeaders["User-Agent"] = true
	}

	// All required headers should be present
	for _, present := range requiredHeaders {
		if !present {
			return false
		}
	}

	return true
}

// extractVPNData extracts actual VPN data hidden in Meet message
func (h *GoogleMeetHandler) extractVPNData(msg *GoogleMeetMessage) ([]byte, error) {
	// VPN data is hidden in the "data" field
	// It could be in various formats to look like WebRTC data

	// Try to extract from "candidate" field (ICE candidates are long strings)
	if encodedData, ok := msg.Data["vpn_payload"].(string); ok {
		return []byte(encodedData), nil
	}

	// Try to extract from SDP description
	if msg.SDP != "" {
		return []byte(msg.SDP), nil
	}

	// Try to extract from candidate field
	if msg.Candidate != "" {
		return []byte(msg.Candidate), nil
	}

	return nil, fmt.Errorf("no VPN data found")
}

// createMeetResponse wraps VPN response data in Google Meet format
func (h *GoogleMeetHandler) createMeetResponse(originalMsg *GoogleMeetMessage, vpnResponse []byte) *GoogleMeetMessage {
	responseType := "answer"
	if originalMsg.Type == "candidate" {
		responseType = "candidate"
	}

	return &GoogleMeetMessage{
		Type:      responseType,
		SessionID: originalMsg.SessionID,
		Timestamp: time.Now().UnixMilli(),
		Data: map[string]interface{}{
			"vpn_payload": string(vpnResponse),
			"status":      "ok",
		},
		SDP: string(vpnResponse), // Hide data in SDP field
	}
}

// RegisterRoutes registers Google Meet protocol routes
func (h *GoogleMeetHandler) RegisterRoutes(mux *http.ServeMux) {
	// Google Meet WebRTC signaling endpoints
	mux.HandleFunc("/meet/signal", h.Handle)
	mux.HandleFunc("/meet/join", h.Handle)
	mux.HandleFunc("/meet/leave", h.Handle)
	mux.HandleFunc("/meet/candidate", h.Handle)

	// Alternative Google Meet-like paths
	mux.HandleFunc("/_/meet/", h.Handle)
	mux.HandleFunc("/video/signaling", h.Handle)
}

/*
Usage Example from Client:

// JavaScript client code that looks like Google Meet
const meetClient = {
  sessionId: generateSessionId(),

  async sendVPNData(data) {
    const meetMessage = {
      type: "offer",
      sessionId: this.sessionId,
      timestamp: Date.now(),
      data: {
        vpn_payload: data  // Your VPN data hidden here
      },
      sdp: btoa(data)  // Also hide in SDP field
    };

    const response = await fetch('https://your-server.com/meet/signal', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'https://meet.google.com',
        'User-Agent': navigator.userAgent
      },
      body: JSON.stringify(meetMessage)
    });

    return await response.json();
  }
};

// Flutter client example
class GoogleMeetProtocol {
  final String sessionId = Uuid().v4();

  Future<Map<String, dynamic>> sendData(Uint8List vpnData) async {
    final meetMessage = {
      'type': 'offer',
      'sessionId': sessionId,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'data': {
        'vpn_payload': base64Encode(vpnData),
      },
      'sdp': base64Encode(vpnData),
    };

    final response = await http.post(
      Uri.parse('$serverUrl/meet/signal'),
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'https://meet.google.com',
        'User-Agent': 'Mozilla/5.0 ...',
      },
      body: json.encode(meetMessage),
    );

    return json.decode(response.body);
  }
}
*/
