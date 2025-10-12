// internal/handlers/wireguard.go

package handlers

import (
	"net/http"

	"orbx-protocol/internal/wireguard"

	"github.com/gin-gonic/gin"
)

type AddPeerRequest struct {
	UserUUID   string `json:"userUuid" binding:"required"`
	PublicKey  string `json:"publicKey" binding:"required"`
	AllowedIPs string `json:"allowedIPs" binding:"required"`
}

type RemovePeerRequest struct {
	UserUUID string `json:"userUuid" binding:"required"`
}

func AddPeer(wgManager *wireguard.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req AddPeerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := wgManager.AddPeer(req.UserUUID, req.PublicKey, req.AllowedIPs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"message":  "Peer added successfully",
			"userUuid": req.UserUUID,
		})
	}
}

func RemovePeer(wgManager *wireguard.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RemovePeerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := wgManager.RemovePeer(req.UserUUID); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"message":  "Peer removed successfully",
			"userUuid": req.UserUUID,
		})
	}
}

func ListPeers(wgManager *wireguard.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		peers := wgManager.GetPeers()

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"count":   len(peers),
			"peers":   peers,
		})
	}
}

func GetStatus(wgManager *wireguard.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Update stats before returning
		wgManager.UpdatePeerStats()

		c.JSON(http.StatusOK, gin.H{
			"success":   true,
			"publicKey": wgManager.GetPublicKey(),
			"peerCount": wgManager.GetPeerCount(),
		})
	}
}
