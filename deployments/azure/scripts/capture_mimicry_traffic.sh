#!/bin/bash
echo "🔬 Capturing OrbX Mimicry Traffic"
echo "=================================="
echo ""
echo "This will capture HTTPS traffic on port 8443 for 30 seconds"
echo "Keep your phone connected and browse something (google.com, etc.)"
echo ""
echo "Press Enter to start capture..."
read

ssh azureuser@172.191.139.108 << 'REMOTE'
echo "📡 Starting packet capture..."
sudo timeout 30 tcpdump -i any -n 'port 8443' -w /tmp/orbx_mimicry.pcap -v

echo ""
echo "✅ Capture complete!"
echo "📊 Capture statistics:"
sudo tcpdump -r /tmp/orbx_mimicry.pcap | wc -l
echo "packets captured"
REMOTE

echo ""
echo "📥 Downloading capture file..."
scp azureuser@172.191.139.108:/tmp/orbx_mimicry.pcap ./orbx_mimicry.pcap

echo ""
echo "✅ Downloaded to: ./orbx_mimicry.pcap"
echo ""
echo "🔍 Quick analysis:"
tcpdump -r orbx_mimicry.pcap -n 'port 8443' 2>/dev/null | head -20

echo ""
echo "📊 To analyze in Wireshark: wireshark orbx_mimicry.pcap"
