//go:build darwin

package netinfo

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// getGatewayIP parses `route -n get default` for the gateway IP.
func getGatewayIP(iface string) (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("route -n get default: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			ip := net.ParseIP(strings.TrimSpace(strings.TrimPrefix(line, "gateway:")))
			if ip == nil {
				return nil, fmt.Errorf("invalid gateway IP in route output")
			}
			return ip.To4(), nil
		}
	}
	return nil, fmt.Errorf("no default route found")
}

var macRe = regexp.MustCompile(`at\s+([0-9a-fA-F:]+)`)

// getARPEntry parses `arp -n <ip>` for the MAC address.
func getARPEntry(ip string) (net.HardwareAddr, error) {
	out, err := exec.Command("arp", "-n", ip).Output()
	if err != nil {
		return nil, fmt.Errorf("arp -n %s: %w", ip, err)
	}
	m := macRe.FindStringSubmatch(string(out))
	if m == nil {
		return nil, fmt.Errorf("ARP entry not found for %s", ip)
	}
	mac, err := net.ParseMAC(m[1])
	if err != nil {
		return nil, err
	}
	return mac, nil
}

// pingGateway sends a single ICMP echo to populate the ARP cache.
func pingGateway(ip string) {
	exec.Command("ping", "-c", "1", "-t", "1", ip).Run()
}

// getGatewayIPv6 parses `route -n get -inet6 default` for the IPv6 gateway.
func getGatewayIPv6(iface string) (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", "-inet6", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("route -n get -inet6 default: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gwStr := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			ip := net.ParseIP(gwStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid gateway IP in route output")
			}
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no default IPv6 route found")
}

// getNDPEntry parses `ndp -an` for the MAC of the given IPv6 address.
func getNDPEntry(ip string) (net.HardwareAddr, error) {
	out, err := exec.Command("ndp", "-an").Output()
	if err != nil {
		return nil, fmt.Errorf("ndp -an: %w", err)
	}

	// Parse output to find IP and extract MAC
	scanner := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(ip) + `\s+([0-9a-fA-F:]+)`)
	m := scanner.FindStringSubmatch(string(out))
	if m == nil {
		return nil, fmt.Errorf("NDP entry not found for %s", ip)
	}
	mac, err := net.ParseMAC(m[1])
	if err != nil {
		return nil, err
	}
	return mac, nil
}

// pingGateway6 sends a single ICMPv6 echo to populate the NDP cache.
func pingGateway6(ip string) {
	exec.Command("ping6", "-c", "1", "-t", "1", ip).Run()
}
