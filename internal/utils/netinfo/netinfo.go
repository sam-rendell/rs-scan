package netinfo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// NetworkDetails holds the discovered configuration.
type NetworkDetails struct {
	SrcIP      net.IP
	SrcMAC     net.HardwareAddr
	GatewayIP  net.IP
	GatewayMAC net.HardwareAddr
}

// GetDetails discovers network info for the given interface.
func GetDetails(ifaceName string) (*NetworkDetails, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %w", err)
	}

	// 1. Get Source MAC
	srcMAC := iface.HardwareAddr

	// 2. Get Source IP
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addrs: %w", err)
	}
	var srcIP net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				srcIP = ipNet.IP.To4()
				break
			}
		}
	}
	if srcIP == nil {
		return nil, fmt.Errorf("no IPv4 address found on %s", ifaceName)
	}

	// 3. Get Gateway IP
	gwIP, err := getGatewayIP(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find gateway: %w", err)
	}

	// 4. Get Gateway MAC
	gwMAC, err := getARPEntry(gwIP.String())
	if err != nil {
		// Try to populate ARP cache by pinging gateway once
		// We ignore the ping error itself, as we just want the ARP side effect.
		exec.Command("ping", "-c", "1", "-W", "1", gwIP.String()).Run()
		time.Sleep(100 * time.Millisecond) // Give kernel a moment
		
		// Retry lookup
		gwMAC, err = getARPEntry(gwIP.String())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve gateway MAC (try pinging %s first): %w", gwIP, err)
		}
	}

	return &NetworkDetails{
		SrcIP:      srcIP,
		SrcMAC:     srcMAC,
		GatewayIP:  gwIP,
		GatewayMAC: gwMAC,
	}, nil
}

// getGatewayIP parses /proc/net/route
func getGatewayIP(iface string) (net.IP, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		// Field 0: Iface, Field 1: Dest, Field 2: Gateway
		if fields[0] == iface && fields[1] == "00000000" {
			// Gateway is in hex little-endian (e.g., 0101A8C0 -> 192.168.1.1)
			gwHex, err := hex.DecodeString(fields[2])
			if err != nil || len(gwHex) != 4 {
				continue
			}
			// Reverse bytes for correct IP
			return net.IPv4(gwHex[3], gwHex[2], gwHex[1], gwHex[0]), nil
		}
	}
	return nil, fmt.Errorf("no default route found")
}

// getARPEntry parses /proc/net/arp
func getARPEntry(ip string) (net.HardwareAddr, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// Field 0: IP, Field 3: MAC
		if fields[0] == ip {
			mac, err := net.ParseMAC(fields[3])
			if err != nil {
				return nil, err
			}
			return mac, nil
		}
	}
	return nil, fmt.Errorf("ARP entry not found for %s", ip)
}

func parseHexIP(s string) (net.IP, error) {
	d, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(d) != 4 {
		return nil, fmt.Errorf("invalid IP length")
	}
	// Little endian to Big endian
	return net.IP{d[3], d[2], d[1], d[0]}, nil
}

// Unused but kept for reference
func ipToUint32(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
