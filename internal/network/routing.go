// internal/network/routing.go
package network

import (
	"fmt"
	"os/exec"
)

// Router manages routing and NAT for VPN traffic
type Router struct {
	tunInterface    string
	publicInterface string
}

// NewRouter creates a new router
func NewRouter(tunInterface, publicInterface string) *Router {
	if publicInterface == "" {
		publicInterface = "eth0" // Default
	}

	return &Router{
		tunInterface:    tunInterface,
		publicInterface: publicInterface,
	}
}

// EnableNAT enables NAT masquerading for VPN traffic
func (r *Router) EnableNAT() error {
	// Enable IP forwarding
	if err := r.enableIPForwarding(); err != nil {
		return err
	}

	// Add iptables NAT rule
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-o", r.publicInterface, "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable NAT: %w", err)
	}

	// Allow forwarding from TUN to public interface
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", r.tunInterface, "-o", r.publicInterface, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add forward rule: %w", err)
	}

	// Allow return traffic
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", r.publicInterface, "-o", r.tunInterface,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add return rule: %w", err)
	}

	return nil
}

// enableIPForwarding enables IP forwarding in kernel
func (r *Router) enableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}
	return nil
}

// DisableNAT removes NAT rules
func (r *Router) DisableNAT() error {
	// Remove NAT rule
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-o", r.publicInterface, "-j", "MASQUERADE")
	cmd.Run() // Ignore errors

	// Remove forward rules
	cmd = exec.Command("iptables", "-D", "FORWARD",
		"-i", r.tunInterface, "-o", r.publicInterface, "-j", "ACCEPT")
	cmd.Run()

	cmd = exec.Command("iptables", "-D", "FORWARD",
		"-i", r.publicInterface, "-o", r.tunInterface,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	cmd.Run()

	return nil
}
