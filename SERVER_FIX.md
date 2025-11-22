# Server-Side Fix for No Data Transfer Issue

## Problem
The server's `/vpn/tunnel` endpoint was **not registering the client's WireGuard peer** before establishing the HTTP tunnel. This caused WireGuard to reject all packets from the client, resulting in VPN connection but no data flow.

## Root Cause
The `handleVPNTunnel()` function in `cmd/server/main.go` was:
1. **Missing** logic to read the `X-WireGuard-PublicKey` header from client requests
2. **Not calling** `wgMgr.AddPeer()` to register the client before tunneling
3. This meant the HTTP tunnel was established, but WireGuard had no authorized peer

Without peer registration:
- ✅ HTTP tunnel establishes successfully
- ✅ WireGuard daemon receives packets through the tunnel
- ❌ **WireGuard rejects packets** because the public key isn't in allowed peers
- ❌ **No handshake completes**
- ❌ **No data flows**

## Changes Made

### File: `cmd/server/main.go`

#### 1. Updated `handleVPNTunnel()` signature (Line 473)
```go
// OLD
func handleVPNTunnel(tunnelMgr *tunnel.HTTPTunnelManager) http.HandlerFunc

// NEW
func handleVPNTunnel(tunnelMgr *tunnel.HTTPTunnelManager, protocolRouter *protocol.Router) http.HandlerFunc
```

#### 2. Added peer registration logic (Lines 511-538)
```go
case "wireguard":
    // ✅ Get client's public key from header
    clientPublicKey := r.Header.Get("X-WireGuard-PublicKey")
    if clientPublicKey == "" {
        log.Printf("❌ Missing X-WireGuard-PublicKey header")
        http.Error(w, "Missing client public key", http.StatusBadRequest)
        return
    }

    log.Printf("🔑 Client public key: %s...", clientPublicKey[:20])

    // ✅ Add peer to WireGuard BEFORE establishing tunnel
    wgMgr := protocolRouter.GetWireGuardHandler()
    if wgMgr == nil {
        log.Printf("❌ WireGuard not enabled")
        http.Error(w, "WireGuard not enabled", http.StatusServiceUnavailable)
        return
    }

    userIDString := fmt.Sprintf("%d", userClaims.UserID)
    clientIP, err := wgMgr.AddPeer(userIDString, clientPublicKey)
    if err != nil {
        log.Printf("❌ Failed to add WireGuard peer: %v", err)
        http.Error(w, "Failed to register peer", http.StatusInternalServerError)
        return
    }

    log.Printf("✅ WireGuard peer added: %s (IP: %s)", clientPublicKey[:20]+"...", clientIP)
```

#### 3. Updated endpoint registration (Lines 134-139)
```go
// Pass protocolRouter to handlers
mux.Handle("/vpn/tunnel", auth.Middleware(jwtAuth,
    http.HandlerFunc(handleVPNTunnel(httpTunnelMgr, protocolRouter))))

mux.Handle("/wireguard/tunnel", auth.Middleware(jwtAuth,
    http.HandlerFunc(handleWireGuardTunnel(httpTunnelMgr, protocolRouter))))
```

#### 4. Updated `handleWireGuardTunnel()` wrapper (Line 566)
```go
func handleWireGuardTunnel(tunnelMgr *tunnel.HTTPTunnelManager, protocolRouter *protocol.Router) http.HandlerFunc
```

## How It Works Now

### Complete Flow:

1. **Client connects**:
   - Generates WireGuard keypair (public + private keys)
   - Sends HTTPS request to `/vpn/tunnel` on port 8443
   - Includes `X-WireGuard-PublicKey` header with client's public key
   - Includes `Authorization: Bearer <token>` header
   - Socket is protected from routing through VPN

2. **Server receives request**:
   - Authenticates via JWT middleware
   - Extracts client's public key from `X-WireGuard-PublicKey` header
   - **Calls `wgMgr.AddPeer()` to register the client**
   - Assigns IP address to client (e.g., 10.8.0.2)
   - Adds client to WireGuard's allowed peers list

3. **HTTP tunnel established**:
   - Server hijacks HTTP connection
   - Sends 200 OK response
   - Connects to local WireGuard interface (127.0.0.1:51820)
   - Starts bidirectional packet forwarding

4. **WireGuard handshake**:
   - Client sends handshake initiation to server's WireGuard
   - **Server recognizes the public key** (it was added in step 2!)
   - Handshake succeeds
   - Encrypted tunnel establishes

5. **Data flows**:
   - Client traffic → HTTPS tunnel → Server's HTTP handler → Local WireGuard → Internet
   - Internet → WireGuard → HTTP handler → HTTPS tunnel → Client
   - All traffic disguised as HTTPS protocol mimicry

## Expected Server Logs

On successful connection, you should see:

```
🎭 User 4 (nima@golsharifi.com) requesting wireguard tunnel with https mimicry
🔑 Client public key: EDXNLCWPT7PJYKBFqVlT...
✅ WireGuard peer added: EDXNLCWPT7PJYKBFqVlT... (IP: 10.8.0.2)
🔵 Establishing HTTP tunnel for user 4 with protocol: https
✅ HTTP tunnel established for user 4
✅ wireguard tunnel established for user 4 with https mimicry
```

## Deployment

1. **Build the server**:
   ```bash
   cd /path/to/orbx-protocol
   go build -o bin/orbx-server ./cmd/server
   ```

2. **Deploy to your server** (Azure VM):
   ```bash
   # Stop current server
   sudo systemctl stop orbx-server

   # Upload new binary
   scp bin/orbx-server user@orbx-eastus-vm.eastus.cloudapp.azure.com:/opt/orbx/

   # Restart server
   sudo systemctl start orbx-server
   sudo systemctl status orbx-server
   ```

3. **Monitor logs**:
   ```bash
   sudo journalctl -u orbx-server -f
   ```

## Testing

After deploying the server, test with the updated Android app:

1. Connect to VPN from Android app
2. Check server logs for peer registration:
   ```
   ✅ WireGuard peer added: <public_key> (IP: 10.8.0.2)
   ```
3. Check WireGuard status on server:
   ```bash
   sudo wg show
   ```
   You should see your peer listed with transfer stats

4. Test internet connectivity:
   - Open browser on phone
   - Visit https://ifconfig.me
   - Should show server's IP address
   - Data counters should increase

## Troubleshooting

If data still doesn't flow:

1. **Check WireGuard peers**:
   ```bash
   sudo wg show
   ```
   Verify your client is listed

2. **Check server logs**:
   ```bash
   sudo journalctl -u orbx-server -n 100
   ```
   Look for peer registration messages

3. **Check firewall**:
   ```bash
   # Ensure ports are open
   sudo ufw status
   sudo ufw allow 8443/tcp  # HTTPS tunnel
   sudo ufw allow 51820/udp # WireGuard
   ```

4. **Verify tunnel is active**:
   ```bash
   sudo netstat -tulpn | grep 51820
   ```

5. **Check packet forwarding**:
   ```bash
   cat /proc/sys/net/ipv4/ip_forward  # Should be 1
   sudo sysctl -w net.ipv4.ip_forward=1  # Enable if needed
   ```

## Related Changes

The Android app was also updated in `/Users/nima/Developments/orbx.flutter`:
- Added `X-WireGuard-PublicKey` header to all HTTP tunnel requests
- Protected tunnel socket from VPN routing
- Added socket timeout and error handling
- Added keepalive loop for tunnel connection

See `HTTP_TUNNEL_FIX.md` in the Flutter project for client-side changes.
