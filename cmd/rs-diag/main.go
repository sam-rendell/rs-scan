package main

import (
	"fmt"
	"net"
	"os"

	"rs_scan/internal/targets"
	"rs_scan/internal/utils/netinfo"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: rs-diag <iface> <target>\n")
		os.Exit(1)
	}
	ifaceName := os.Args[1]
	targetStr := os.Args[2]

	fmt.Println("=== netinfo.GetDetails ===")
	details, err := netinfo.GetDetails(ifaceName)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SrcIP:        %v\n", details.SrcIP)
	fmt.Printf("SrcMAC:       %v (len=%d)\n", details.SrcMAC, len(details.SrcMAC))
	fmt.Printf("GatewayIP:    %v\n", details.GatewayIP)
	fmt.Printf("GatewayMAC:   %v\n", details.GatewayMAC)
	fmt.Printf("SrcIPv6:      %v\n", details.SrcIPv6)
	fmt.Printf("GatewayIPv6:  %v\n", details.GatewayIPv6)
	fmt.Printf("GatewayMACv6: %v\n", details.GatewayMACv6)
	fmt.Printf("IsTUN:        %v\n", details.IsTUN)
	fmt.Printf("hasIPv6Source: %v\n", details.SrcIPv6 != nil)

	fmt.Println("\n=== Target Parsing ===")
	ip := net.ParseIP(targetStr)
	fmt.Printf("net.ParseIP(%q) = %v\n", targetStr, ip)
	if ip != nil {
		ipAddr := targets.FromNetIP(ip)
		fmt.Printf("IPAddr.IsIPv4(): %v\n", ipAddr.IsIPv4())
		fmt.Printf("IPAddr.String(): %s\n", ipAddr.String())
		fmt.Printf("IPAddr bytes:    %x\n", [16]byte(ipAddr))
	}

	fmt.Println("\n=== TupleIterator ===")
	iter, err := targets.NewTupleIterator([]string{targetStr}, "80,443", nil)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}
	fmt.Printf("TotalIPs: %d, TotalPorts: %d\n", iter.TotalIPs(), iter.TotalPorts())
	for i := 0; i < 4; i++ {
		tIP, tPort, ok := iter.Next()
		if !ok {
			break
		}
		fmt.Printf("  tuple[%d]: IP=%s port=%d isIPv4=%v\n", i, tIP.String(), tPort, tIP.IsIPv4())
	}

	// Key question: what does the GRE interface HardwareAddr look like?
	iface, _ := net.InterfaceByName(ifaceName)
	if iface != nil {
		fmt.Printf("\n=== Interface Details ===\n")
		fmt.Printf("Name:       %s\n", iface.Name)
		fmt.Printf("MTU:        %d\n", iface.MTU)
		fmt.Printf("Flags:      %v\n", iface.Flags)
		fmt.Printf("HardwareAddr: %v (len=%d, bytes=%x)\n", iface.HardwareAddr, len(iface.HardwareAddr), []byte(iface.HardwareAddr))
	}
}
