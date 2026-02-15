package netinfo

import (
	"fmt"
	"net"
	"time"
)

// NetworkDetails holds the discovered configuration.
type NetworkDetails struct {
	SrcIP        net.IP
	SrcMAC       net.HardwareAddr
	GatewayIP    net.IP
	GatewayMAC   net.HardwareAddr
	SrcIPv6      net.IP
	GatewayIPv6  net.IP
	GatewayMACv6 net.HardwareAddr
	IsTUN        bool
}

// GetDetails discovers network info for the given interface.
func GetDetails(ifaceName string) (*NetworkDetails, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %w", err)
	}

	// 1. Get Source MAC (empty for TUN/point-to-point interfaces)
	srcMAC := iface.HardwareAddr

	// 2. Get Source IP (IPv4 and IPv6)
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addrs: %w", err)
	}
	var srcIP net.IP
	var srcIPv6 net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				if srcIP == nil {
					srcIP = ipNet.IP.To4()
				}
			} else if ipNet.IP.To16() != nil && !ipNet.IP.IsLinkLocalUnicast() {
				// Skip link-local (fe80::/10), only use global-scope IPv6
				if srcIPv6 == nil {
					srcIPv6 = ipNet.IP
				}
			}
		}
	}
	if srcIP == nil && srcIPv6 == nil {
		return nil, fmt.Errorf("no IP address found on %s", ifaceName)
	}

	// Loopback or TUN/point-to-point: no gateway discovery needed
	if len(srcMAC) == 0 || (srcIP != nil && srcIP.IsLoopback()) {
		return &NetworkDetails{
			SrcIP:   srcIP,
			SrcIPv6: srcIPv6,
			IsTUN:   true,
		}, nil
	}

	// IPv6-only interface with MAC (rare but possible): skip IPv4 gateway
	if srcIP == nil {
		var gwIPv6 net.IP
		var gwMACv6 net.HardwareAddr
		gwIPv6, err = getGatewayIPv6(ifaceName)
		if err == nil && gwIPv6 != nil {
			gwMACv6, err = getNDPEntry(gwIPv6.String())
			if err != nil {
				pingGateway6(gwIPv6.String())
				time.Sleep(100 * time.Millisecond)
				gwMACv6, _ = getNDPEntry(gwIPv6.String())
			}
		}
		return &NetworkDetails{
			SrcMAC:       srcMAC,
			SrcIPv6:      srcIPv6,
			GatewayIPv6:  gwIPv6,
			GatewayMACv6: gwMACv6,
		}, nil
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
		pingGateway(gwIP.String())
		time.Sleep(100 * time.Millisecond) // Give kernel a moment

		// Retry lookup
		gwMAC, err = getARPEntry(gwIP.String())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve gateway MAC (try pinging %s first): %w", gwIP, err)
		}
	}

	// 5. IPv6 Gateway Discovery (optional, non-fatal)
	var gwIPv6 net.IP
	var gwMACv6 net.HardwareAddr
	if srcIPv6 != nil {
		gwIPv6, err = getGatewayIPv6(ifaceName)
		if err == nil && gwIPv6 != nil {
			// Try to get gateway MAC via NDP
			gwMACv6, err = getNDPEntry(gwIPv6.String())
			if err != nil {
				// Try to populate NDP cache by pinging
				pingGateway6(gwIPv6.String())
				time.Sleep(100 * time.Millisecond)
				gwMACv6, _ = getNDPEntry(gwIPv6.String())
				// Ignore error - IPv6 gateway MAC is optional
			}
		}
		// Ignore IPv6 gateway discovery errors - it's optional
	}

	return &NetworkDetails{
		SrcIP:        srcIP,
		SrcMAC:       srcMAC,
		GatewayIP:    gwIP,
		GatewayMAC:   gwMAC,
		SrcIPv6:      srcIPv6,
		GatewayIPv6:  gwIPv6,
		GatewayMACv6: gwMACv6,
	}, nil
}
