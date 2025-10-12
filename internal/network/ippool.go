package network

import (
	"fmt"
	"net"
	"sync"
)

// IPPool manages IP address allocation for VPN clients
type IPPool struct {
	cidr      *net.IPNet
	gateway   net.IP
	available []net.IP
	allocated map[string]net.IP // userID -> IP
	mu        sync.RWMutex
}

// NewIPPool creates a new IP pool from CIDR
func NewIPPool(cidr string) (*IPPool, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	pool := &IPPool{
		cidr:      ipNet,
		gateway:   incrementIP(ipNet.IP, 1), // First IP is gateway
		available: make([]net.IP, 0),
		allocated: make(map[string]net.IP),
	}

	// Generate available IPs (skip network, gateway, broadcast)
	ip := incrementIP(ipNet.IP, 2) // Start after gateway
	for ipNet.Contains(ip) {
		// Skip broadcast address
		if !isBroadcast(ip, ipNet) {
			pool.available = append(pool.available, copyIP(ip))
		}
		ip = incrementIP(ip, 1)
	}

	return pool, nil
}

// AllocateIP assigns an IP to a user
func (p *IPPool) AllocateIP(userID string) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if user already has an IP
	if ip, exists := p.allocated[userID]; exists {
		return ip, nil
	}

	// Check if pool is exhausted
	if len(p.available) == 0 {
		return nil, fmt.Errorf("IP pool exhausted")
	}

	// Allocate first available IP
	ip := p.available[0]
	p.available = p.available[1:]
	p.allocated[userID] = ip

	return ip, nil
}

// ReleaseIP returns an IP to the pool
func (p *IPPool) ReleaseIP(userID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip, exists := p.allocated[userID]
	if !exists {
		return fmt.Errorf("no IP allocated to user: %s", userID)
	}

	delete(p.allocated, userID)
	p.available = append(p.available, ip)

	return nil
}

// GetGateway returns the gateway IP
func (p *IPPool) GetGateway() net.IP {
	return p.gateway
}

// GetCIDR returns the network CIDR
func (p *IPPool) GetCIDR() *net.IPNet {
	return p.cidr
}

// Helper functions
func incrementIP(ip net.IP, inc uint) net.IP {
	newIP := copyIP(ip)
	for i := len(newIP) - 1; i >= 0 && inc > 0; i-- {
		newVal := uint(newIP[i]) + inc
		newIP[i] = byte(newVal & 0xFF)
		inc = newVal >> 8
	}
	return newIP
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func isBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^ipNet.Mask[i]
	}
	return ip.Equal(broadcast)
}
