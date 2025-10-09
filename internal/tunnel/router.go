// internal/tunnel/router.go
package tunnel

import (
	"fmt"
	"net"
	"sync"
)

// Router handles packet routing through the tunnel
type Router struct {
	routes map[string]*Route
	mu     sync.RWMutex
}

// Route represents a routing rule
type Route struct {
	Destination string
	Gateway     string
	Interface   string
}

// NewRouter creates a new packet router
func NewRouter() *Router {
	return &Router{
		routes: make(map[string]*Route),
	}
}

// AddRoute adds a routing rule
func (r *Router) AddRoute(destination, gateway, iface string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes[destination] = &Route{
		Destination: destination,
		Gateway:     gateway,
		Interface:   iface,
	}
}

// RemoveRoute removes a routing rule
func (r *Router) RemoveRoute(destination string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.routes, destination)
}

// RoutePacket determines the route for a packet
func (r *Router) RoutePacket(destIP net.IP) (*Route, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check for specific route
	if route, exists := r.routes[destIP.String()]; exists {
		return route, nil
	}

	// Check for network routes
	for dest, route := range r.routes {
		_, network, err := net.ParseCIDR(dest)
		if err != nil {
			continue
		}

		if network.Contains(destIP) {
			return route, nil
		}
	}

	// Default route
	if defaultRoute, exists := r.routes["0.0.0.0/0"]; exists {
		return defaultRoute, nil
	}

	return nil, fmt.Errorf("no route to host: %s", destIP)
}

// GetRoutes returns all routes
func (r *Router) GetRoutes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*Route, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}

	return routes
}

// Clear removes all routes
func (r *Router) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = make(map[string]*Route)
}
