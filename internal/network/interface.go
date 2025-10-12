// internal/network/interface.go
package network

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

// TunInterface manages the TUN network interface
type TunInterface struct {
	device tun.Device
	name   string
	ipPool *IPPool
	mtu    int
}

// NewTunInterface creates and configures a TUN interface
func NewTunInterface(name string, ipPool *IPPool, mtu int) (*TunInterface, error) {
	// Create TUN device
	device, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	realName, err := device.Name()
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to get TUN device name: %w", err)
	}

	tunIface := &TunInterface{
		device: device,
		name:   realName,
		ipPool: ipPool,
		mtu:    mtu,
	}

	// Configure the interface
	if err := tunIface.configure(); err != nil {
		device.Close()
		return nil, err
	}

	return tunIface, nil
}

// configure sets up the TUN interface with IP and routes
func (t *TunInterface) configure() error {
	// Get the link
	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to get link: %w", err)
	}

	// Set MTU
	if err := netlink.LinkSetMTU(link, t.mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Add IP address (gateway)
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   t.ipPool.GetGateway(),
			Mask: t.ipPool.GetCIDR().Mask,
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}

	// Bring interface up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// Device returns the underlying TUN device
func (t *TunInterface) Device() tun.Device {
	return t.device
}

// Name returns the interface name
func (t *TunInterface) Name() string {
	return t.name
}

// Close closes the TUN interface
func (t *TunInterface) Close() error {
	return t.device.Close()
}
