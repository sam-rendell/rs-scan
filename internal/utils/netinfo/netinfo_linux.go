//go:build linux

package netinfo

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// getGatewayIP parses /proc/net/route for the default gateway.
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
		if fields[0] == iface && fields[1] == "00000000" {
			gwHex, err := hex.DecodeString(fields[2])
			if err != nil || len(gwHex) != 4 {
				continue
			}
			return net.IPv4(gwHex[3], gwHex[2], gwHex[1], gwHex[0]), nil
		}
	}
	return nil, fmt.Errorf("no default route found")
}

// getARPEntry parses /proc/net/arp for the MAC of the given IP.
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

// pingGateway sends a single ICMP echo to populate the ARP cache.
func pingGateway(ip string) {
	exec.Command("ping", "-c", "1", "-W", "1", ip).Run()
}

// getGatewayIPv6 parses /proc/net/ipv6_route for the default gateway.
func getGatewayIPv6(iface string) (net.IP, error) {
	data, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		// Format: dest dest_prefix src src_prefix nexthop metric refcnt use flags iface
		// Default route: dest=00000000000000000000000000000000, dest_prefix=00
		dest := fields[0]
		destPrefix := fields[1]
		nexthop := fields[4]
		ifaceName := fields[9]

		if dest == "00000000000000000000000000000000" && destPrefix == "00" && ifaceName == iface {
			// Skip if nexthop is all zeros (directly connected)
			if nexthop == "00000000000000000000000000000000" {
				continue
			}
			// Parse nexthop hex (32 hex chars = 16 bytes)
			gwBytes, err := hex.DecodeString(nexthop)
			if err != nil || len(gwBytes) != 16 {
				continue
			}
			return net.IP(gwBytes), nil
		}
	}
	return nil, fmt.Errorf("no default IPv6 route found")
}

// getNDPEntry parses `ip -6 neigh show` for the MAC of the given IPv6 address.
func getNDPEntry(ip string) (net.HardwareAddr, error) {
	out, err := exec.Command("ip", "-6", "neigh", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("ip -6 neigh show: %w", err)
	}

	// Parse lines like: "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[0] == ip {
			// Find lladdr field
			for i := 0; i < len(fields)-1; i++ {
				if fields[i] == "lladdr" {
					mac, err := net.ParseMAC(fields[i+1])
					if err != nil {
						return nil, err
					}
					return mac, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("NDP entry not found for %s", ip)
}

// pingGateway6 sends a single ICMPv6 echo to populate the NDP cache.
func pingGateway6(ip string) {
	exec.Command("ping", "-6", "-c", "1", "-W", "1", ip).Run()
}
