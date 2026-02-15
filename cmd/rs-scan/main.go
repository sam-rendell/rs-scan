package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"rs_scan/internal/banner"
	"rs_scan/internal/config"
	"rs_scan/internal/limiter"
	"rs_scan/internal/osfp"
	"rs_scan/internal/output"
	"rs_scan/internal/receiver"
	"rs_scan/internal/sender"
	"rs_scan/internal/stack"
	"rs_scan/internal/targets"
	"rs_scan/internal/ui"
	"rs_scan/internal/utils/netinfo"

	"rs_scan/internal/version"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mattn/go-isatty"
)

var running int32 = 1

// dataDir is set at build time: -ldflags "-X main.dataDir=/usr/local/share/rs-scan/probes"
var dataDir string

// resolveProbeDir finds the probe directory for a given protocol (tcp/udp).
// Search order: RS_SCAN_DATA env, -probes flag, compile-time dataDir, binary-relative, CWD.
func resolveProbeDir(probeFlag, proto string) string {
	candidates := []string{}

	// 1. RS_SCAN_DATA env
	if env := os.Getenv("RS_SCAN_DATA"); env != "" {
		candidates = append(candidates, filepath.Join(env, proto))
	}

	// 2. -probes flag + /<proto>, then -probes flag as-is
	if probeFlag != "" {
		candidates = append(candidates, filepath.Join(probeFlag, proto))
		candidates = append(candidates, probeFlag)
	}

	// 3. Compile-time dataDir
	if dataDir != "" {
		candidates = append(candidates, filepath.Join(dataDir, proto))
	}

	// 4. Binary-relative
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "probes", proto))
	}

	// 5. CWD
	candidates = append(candidates, filepath.Join("probes", proto))

	for _, dir := range candidates {
		if hasYAMLFiles(dir) {
			return dir
		}
	}
	return ""
}

func hasYAMLFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			return true
		}
	}
	return false
}

func main() {
	// ── CLI Flags ──────────────────────────────────────────────────────
	// Original flags
	iface := flag.String("i", "wlp0s20f3", "Interface")
	ifaceAlias := flag.String("e", "", "Interface (alias for -i)")
	outputFile := flag.String("o", "output.jsonl", "Output file")
	oJ := flag.String("oJ", "", "JSON output file (alias for -o)")
	oG := flag.String("oG", "", "Grepable output file")
	targetFlag := flag.String("t", "", "Target")
	portFlag := flag.String("p", "80", "Ports (supports T:/U: prefix)")
	ppsFlag := flag.Int("pps", 1000, "Packets per second")
	rateFlag := flag.Int("rate", 0, "Packets per second (alias for -pps)")
	bannerGrabFlag := flag.Bool("banner-grab", false, "Enable banner grab")
	bannersFlag := flag.Bool("banners", false, "Enable banner grab (alias)")
	shardsFlag := flag.Int("shards", 1, "Sender threads")
	timeoutFlag := flag.Duration("timeout", 5*time.Second, "Timeout")
	waitFlag := flag.Int("wait", 0, "Timeout in seconds (alias for -timeout)")
	verboseFlag := flag.Bool("v", false, "Verbose output (log timeouts)")
	debugFlag := flag.Bool("debug", false, "Debug mode (packet-level diagnostics)")
	probeDir := flag.String("probes", "", "Path to probe YAML directory")
	arenaSlots := flag.Int("arena-slots", 100000, "Max concurrent banner grabs")

	// New scan mode flags
	scanSS := flag.Bool("sS", false, "TCP SYN scan (default)")
	scanSU := flag.Bool("sU", false, "UDP scan")

	// New input flags
	inputList := flag.String("iL", "", "Target list from file (one per line)")
	excludeFlag := flag.String("exclude", "", "Exclusion list (comma-separated)")
	excludeFile := flag.String("excludefile", "", "Exclusion list from file")

	// UDP retransmit
	retriesFlag := flag.Int("retries", 1, "UDP retransmit count")

	// VPN/tunnel overrides
	sourceIPFlag := flag.String("S", "", "Source IP override (for VPN scanning)")
	gwMACFlag := flag.String("gw-mac", "", "Gateway MAC override (aa:bb:cc:dd:ee:ff)")

	// NAT64 prefix mapping
	nat64Flag := flag.String("nat64", "", "NAT64 /96 prefix (e.g. 2001:67c:2960:6464)")

	// Sequential mode
	sequentialFlag := flag.Bool("sequential", false, "Scan targets in order (no randomization)")

	// Output filtering
	openOnlyFlag := flag.Bool("open", false, "Only log open/banner results")

	// Webhook output
	webhookURL := flag.String("webhook", "", "Webhook URL (HTTP POST batched JSONL)")

	// Config file
	configFile := flag.String("c", "", "Config file (YAML)")

	// UI mode flags
	quietFlag := flag.Bool("q", false, "Silent mode (no terminal output)")
	quietAlias := flag.Bool("quiet", false, "Silent mode (alias for -q)")
	noTUI := flag.Bool("no-tui", false, "Disable TUI (text mode)")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("rs-scan version %s\n", version.Version)
		return
	}

	// ── Apply config file (CLI flags override) ───────────────────────
	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	var cfg *config.Config
	if *configFile != "" {
		var cfgErr error
		cfg, cfgErr = config.LoadConfig(*configFile)
		if cfgErr != nil {
			log.Fatalf("failed to load config %s: %v", *configFile, cfgErr)
		}
		applyConfig(cfg, setFlags, iface, portFlag, ppsFlag, shardsFlag,
			timeoutFlag, retriesFlag, arenaSlots, sourceIPFlag, gwMACFlag,
			probeDir, outputFile, oG, webhookURL, bannerGrabFlag, sequentialFlag,
			openOnlyFlag, verboseFlag, debugFlag, quietFlag, noTUI,
			scanSS, scanSU)
	}

	// ── Resolve aliases ────────────────────────────────────────────────
	if *ifaceAlias != "" {
		*iface = *ifaceAlias
	}
	if *oJ != "" {
		*outputFile = *oJ
	}
	if *rateFlag > 0 {
		*ppsFlag = *rateFlag
	}
	if *bannersFlag {
		*bannerGrabFlag = true
	}
	if *waitFlag > 0 {
		*timeoutFlag = time.Duration(*waitFlag) * time.Second
	}
	if *quietAlias {
		*quietFlag = true
	}

	// ── Stdout JSONL detection ────────────────────────────────────────
	stdoutOutput := *outputFile == "-"
	if cfg != nil && cfg.Output.Stdout {
		stdoutOutput = true
	}
	if stdoutOutput {
		*noTUI = true // bubbletea renders to stdout — force text/silent mode
	}

	// ── Scan mode ──────────────────────────────────────────────────────
	doTCP := true
	doUDP := false
	if *scanSU && !*scanSS {
		doTCP = false
		doUDP = true
	} else if *scanSU && *scanSS {
		doTCP = true
		doUDP = true
	}
	// Default: doTCP=true, doUDP=false (TCP SYN only)

	scanModeStr := "TCP SYN"
	if doTCP && doUDP {
		scanModeStr = "TCP SYN + UDP"
	} else if doUDP {
		scanModeStr = "UDP"
	}

	// Determine default proto for bare ports
	defaultProto := "tcp"
	if doUDP && !doTCP {
		defaultProto = "udp"
	} else if doUDP && doTCP {
		defaultProto = "both"
	}

	// ── UI mode ────────────────────────────────────────────────────────
	var uiMode ui.Mode
	if *quietFlag {
		uiMode = ui.ModeSilent
	} else if *noTUI || !isatty.IsTerminal(os.Stdout.Fd()) {
		uiMode = ui.ModeText
	} else {
		uiMode = ui.ModeTUI
	}

	// ── Build target list ──────────────────────────────────────────────
	var targetList []string
	if cfg != nil {
		targetList = append(targetList, cfg.Scan.Targets.Include...)
	}
	if *targetFlag != "" {
		targetList = append(targetList, *targetFlag)
	}
	targetList = append(targetList, flag.Args()...)
	if *inputList != "" {
		lines, err := readLines(*inputList)
		if err != nil {
			log.Fatalf("failed to read target list: %v", err)
		}
		targetList = append(targetList, lines...)
	}
	if len(targetList) == 0 {
		log.Fatal("no targets specified (use -t, positional args, -iL, or -c)")
	}

	// ── Build exclusion list ───────────────────────────────────────────
	var excludeList []string
	if cfg != nil {
		excludeList = append(excludeList, cfg.Scan.Targets.Exclude...)
	}
	if *excludeFlag != "" {
		excludeList = append(excludeList, strings.Split(*excludeFlag, ",")...)
	}
	if *excludeFile != "" {
		lines, err := readLines(*excludeFile)
		if err != nil {
			log.Fatalf("failed to read exclude file: %v", err)
		}
		excludeList = append(excludeList, lines...)
	}

	// ── Parse ports with protocol support ──────────────────────────────
	tcpPorts, udpPorts, err := targets.ParsePortSpec(*portFlag, defaultProto)
	if err != nil {
		log.Fatalf("invalid port spec: %v", err)
	}
	if doTCP && len(tcpPorts) == 0 && doUDP && len(udpPorts) == 0 {
		log.Fatal("no ports to scan")
	}

	// ── NAT64 prefix ─────────────────────────────────────────────────
	var nat64Prefix *[12]byte
	if *nat64Flag != "" {
		p, err := targets.ParseNAT64Prefix(*nat64Flag)
		if err != nil {
			log.Fatalf("NAT64: %v", err)
		}
		nat64Prefix = &p
	}

	// ── Build iterators ────────────────────────────────────────────────
	var tcpIter *targets.TupleIterator
	var udpIter *targets.TupleIterator

	newIter := func(portStr string) (*targets.TupleIterator, error) {
		if nat64Prefix != nil {
			return targets.NewNAT64TupleIterator(*nat64Prefix, targetList, portStr, excludeList, *sequentialFlag)
		}
		return targets.NewTupleIterator(targetList, portStr, excludeList, *sequentialFlag)
	}

	if doTCP && len(tcpPorts) > 0 {
		portStr := portsToString(tcpPorts)
		tcpIter, err = newIter(portStr)
		if err != nil {
			log.Fatalf("TCP iterator: %v", err)
		}
	}
	if doUDP && len(udpPorts) > 0 {
		portStr := portsToString(udpPorts)
		udpIter, err = newIter(portStr)
		if err != nil {
			log.Fatalf("UDP iterator: %v", err)
		}
	}

	// ── Network Discovery ──────────────────────────────────────────────
	details, err := netinfo.GetDetails(*iface)
	if err != nil {
		log.Fatal(err)
	}
	isTUN := details.IsTUN
	sIP, sMAC, dMAC := details.SrcIP, details.SrcMAC, details.GatewayMAC

	// Apply VPN/tunnel overrides
	if *sourceIPFlag != "" {
		override := net.ParseIP(*sourceIPFlag)
		if override == nil {
			log.Fatalf("invalid source IP: %s", *sourceIPFlag)
		}
		if v4 := override.To4(); v4 != nil {
			sIP = v4
		} else {
			sIP = nil // IPv6-only override
			details.SrcIPv6 = override
		}
	}
	if *gwMACFlag != "" {
		var parseErr error
		dMAC, parseErr = net.ParseMAC(*gwMACFlag)
		if parseErr != nil {
			log.Fatalf("invalid gateway MAC: %s", *gwMACFlag)
		}
	}

	var srcIPAddr targets.IPAddr
	if sIP != nil {
		srcIPAddr = targets.FromNetIP(sIP)
	}

	// IPv6 source configuration (optional — dual-stack when available)
	var srcIPv6Bytes [16]byte
	var srcIPv6Addr targets.IPAddr // IPv6 source for connection table keying
	hasIPv6Source := details.SrcIPv6 != nil
	if hasIPv6Source {
		copy(srcIPv6Bytes[:], details.SrcIPv6.To16())
		srcIPv6Addr = targets.FromNetIP(details.SrcIPv6)
	}
	// Use v6 gateway MAC if available, fall back to v4 gateway MAC
	gwMACv6 := details.GatewayMACv6
	if gwMACv6 == nil && dMAC != nil {
		gwMACv6 = dMAC
	}

	// ── Components ─────────────────────────────────────────────────────
	connTable := stack.NewConnectionTable()

	// Output sink: fan out to multiple writers
	sink := output.NewOutputSink()

	if stdoutOutput {
		sink.Add(output.NewStdoutWriter(4096))
	} else {
		outWriter, err := output.NewWriter(*outputFile)
		if err != nil {
			log.Fatalf("failed to open output file: %v", err)
		}
		sink.Add(outWriter)
	}

	// Grepable output
	if *oG != "" {
		grepFile, err := os.OpenFile(*oG, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open grepable output file: %v", err)
		}
		grepFmt := output.NewGrepFormatter(grepFile)
		sink.Add(output.NewClosingWriter(grepFmt, grepFile))
	}

	// Webhook output
	webhookAddr := *webhookURL
	if webhookAddr == "" && cfg != nil && cfg.Output.Webhook != nil && cfg.Output.Webhook.URL != "" {
		webhookAddr = cfg.Output.Webhook.URL
	}
	if webhookAddr != "" {
		whCfg := output.WebhookConfig{URL: webhookAddr}
		if cfg != nil && cfg.Output.Webhook != nil {
			wh := cfg.Output.Webhook
			whCfg.BatchSize = wh.BatchSize
			whCfg.MaxRetries = wh.MaxRetries
			whCfg.Headers = wh.Headers
			if wh.Timeout.Duration > 0 {
				whCfg.Timeout = wh.Timeout.Duration
			}
		}
		sink.Add(output.NewWebhookWriter(whCfg))
	}

	var recv *receiver.Listener
	if isTUN {
		recv, err = receiver.NewTunnelListener(*iface)
	} else {
		recv, err = receiver.NewListener(*iface)
	}
	if err != nil {
		log.Fatal(err)
	}

	// ── BPF filter based on scan mode ──────────────────────────────────
	var bpfFilter string
	v4Match, v6Match := "tcp", "tcp"
	switch {
	case doTCP && doUDP:
		v4Match = "(tcp or udp or (icmp and icmp[icmptype]==3))"
		v6Match = "(tcp or udp or icmp6)"
	case doUDP:
		v4Match = "(udp or (icmp and icmp[icmptype]==3))"
		v6Match = "(udp or icmp6)"
	}
	switch {
	case sIP != nil && hasIPv6Source:
		bpfFilter = fmt.Sprintf("(%s and dst host %s) or (ip6 and %s and dst host %s)",
			v4Match, sIP.String(), v6Match, details.SrcIPv6.String())
	case sIP != nil:
		bpfFilter = fmt.Sprintf("%s and dst host %s", v4Match, sIP.String())
	case hasIPv6Source:
		bpfFilter = fmt.Sprintf("ip6 and %s and dst host %s", v6Match, details.SrcIPv6.String())
	default:
		log.Fatal("no source IP (IPv4 or IPv6) — cannot build BPF filter")
	}
	if err := recv.SetBPF(*iface, bpfFilter); err != nil {
		log.Fatalf("failed to set BPF filter: %v", err)
	}

	// ── Events channel ─────────────────────────────────────────────────
	events := make(chan ui.ScanEvent, 10000)
	emitEvent := func(ev ui.ScanEvent) {
		select {
		case events <- ev:
		default: // drop if full
		}
	}

	// ── Banner Engine Setup (optional, TCP only) ───────────────────────
	var engine *banner.Engine
	var responder *banner.Responder
	var grabOutput chan banner.GrabResult
	var grabDone chan struct{}
	var bannerCount uint64

	// Load UDP probe table (for UDP sender payloads)
	var udpProbeTable *banner.ProbeTable
	if doUDP {
		udpProbeTable = banner.NewProbeTable()
		pDir := resolveProbeDir(*probeDir, "udp")
		if pDir == "" {
			log.Printf("warning: no UDP probe directory found")
		} else if err := udpProbeTable.LoadProbes(pDir); err != nil {
			log.Printf("warning: failed to load UDP probes from %s: %v", pDir, err)
		} else {
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Loaded %d UDP probes from %s", len(udpProbeTable.Probes), pDir)})
		}
	}

	if *bannerGrabFlag && doTCP {
		pDir := resolveProbeDir(*probeDir, "tcp")
		probeTable := banner.NewProbeTable()
		if pDir == "" {
			log.Printf("warning: no TCP probe directory found (using generic passive grabs)")
		} else if err := probeTable.LoadProbes(pDir); err != nil {
			log.Printf("warning: failed to load probes from %s: %v (using generic passive grabs)", pDir, err)
		} else {
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Loaded %d TCP probes from %s", len(probeTable.Probes), pDir)})
		}

		arena := banner.NewArena(uint32(*arenaSlots), 512)
		txRing := banner.NewTXRing(65536)
		grabOutput = make(chan banner.GrabResult, 10000)

		engine = banner.NewEngine(banner.EngineConfig{
			Arena:       arena,
			TXRing:      txRing,
			Probes:      probeTable,
			ConnTable:   connTable,
			SrcIP:       stack.IPAddr(srcIPAddr),
			Output:      grabOutput,
			Phase1MS:    500,
			ConnTimeout: *timeoutFlag,
			Running:     &running,
		})

		var rErr error
		responder, rErr = banner.NewResponder(*iface, sMAC, dMAC, sIP, txRing, &running)
		if rErr != nil {
			log.Fatalf("failed to create responder: %v", rErr)
		}

		go responder.Run()
		if hasIPv6Source {
			responder.ConfigureIPv6(srcIPv6Bytes, sMAC, gwMACv6)
		}

		grabDone = make(chan struct{})
		go func() {
			defer close(grabDone)
			for gr := range grabOutput {
				atomic.AddUint64(&bannerCount, 1)
				ip := stackIPToString(gr.IP)
				logResult(sink, events, ip, gr.Port, gr.TTL, string(gr.Banner), "BANNER", gr.Probe, "tcp", *openOnlyFlag, nil, nil)
			}
		}()

		if !checkRSTSuppression() {
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: "WARNING: no RST suppression — banner grabs will be unreliable"})
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("  run: %s", rstSuppressionHint())})
		}
		if hasIPv6Source && !checkRSTSuppressionV6() {
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: "WARNING: no IPv6 RST suppression"})
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("  run: %s", rstSuppressionHintV6())})
		}

		emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Banner grab enabled: %d arena slots", *arenaSlots)})
	}

	// Legacy ACK sender (TCP, no banner engine)
	var legacyAckSender *sender.RingSender
	if doTCP && !*bannerGrabFlag {
		legacyAckSender, err = sender.NewRingSender(*iface, sMAC, dMAC, sIP)
		if err != nil {
			log.Fatalf("failed to create ACK sender: %v", err)
		}
		if hasIPv6Source {
			legacyAckSender.ConfigureIPv6(srcIPv6Bytes, sMAC, gwMACv6)
		}
	}

	if isTUN {
		srcStr := "<none>"
		if sIP != nil {
			srcStr = sIP.String()
		}
		emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Source: %s (TUN), Interface: %s", srcStr, *iface)})
	} else if sIP != nil {
		emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Source: %s (%s), Gateway: %s", sIP, sMAC, dMAC)})
	}
	if hasIPv6Source {
		emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("IPv6: %s", details.SrcIPv6)})
	}
	emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Scan: %s, Filter: %s", scanModeStr, bpfFilter)})

	// Log search space (previously printed to stdout from tuple.go)
	if tcpIter != nil {
		emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("TCP: %d IPs * %d ports = %d tuples", tcpIter.TotalIPs(), tcpIter.TotalPorts(), getTotalSize(tcpIter))})
	}
	if udpIter != nil {
		emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("UDP: %d IPs * %d ports = %d tuples", udpIter.TotalIPs(), udpIter.TotalPorts(), getTotalSize(udpIter))})
	}

	// ── Receiver Loop ──────────────────────────────────────────────────
	var recvPackets uint64
	var foundOpen uint64
	var debugLookupHit, debugLookupMiss uint64
	debug := *debugFlag
	var ethL layers.Ethernet
	var sllL layers.LinuxSLL
	var ipL layers.IPv4
	var ip6L layers.IPv6
	var tcpL layers.TCP
	var udpL layers.UDP
	var icmpL layers.ICMPv4
	var icmp6L layers.ICMPv6
	var parser *gopacket.DecodingLayerParser
	var parser6 *gopacket.DecodingLayerParser // IPv6 parser for TUN mode (raw socket)
	switch {
	case recv.UseSLL:
		// Tunnel via pcap: Linux SLL header → IPv4/IPv6
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeLinuxSLL,
			&sllL, &ipL, &ip6L, &tcpL, &udpL, &icmpL, &icmp6L)
	case isTUN:
		// Raw TUN (e.g. WireGuard): no link header, raw IP
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4,
			&ipL, &tcpL, &udpL, &icmpL)
		parser6 = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6,
			&ip6L, &tcpL, &udpL, &icmp6L)
		parser6.IgnoreUnsupported = true
	default:
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
			&ethL, &ipL, &ip6L, &tcpL, &udpL, &icmpL, &icmp6L)
	}
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 0, 8)
	recvDone := make(chan struct{})

	// SAFETY: On Linux, ReadPacket() wraps ZeroCopyReadPacketData — the returned
	// buffer is only valid until the next ReadPacket() call. All processing
	// (decode, state update, banner engine handoff) MUST complete within this
	// iteration. Never pass 'data' to a goroutine or store it.
	go func() {
		defer close(recvDone)
		for atomic.LoadInt32(&running) == 1 {
			data, _, err := recv.Handle.ReadPacket()
			if err != nil {
				continue
			}

			// TUN: check IP version nibble to select parser
			p := parser
			if parser6 != nil && len(data) > 0 && data[0]>>4 == 6 {
				p = parser6
			}
			if err := p.DecodeLayers(data, &decoded); err != nil {
				continue
			}

			hasTCP, hasUDP, hasICMP, hasIPv6, hasICMPv6 := false, false, false, false, false
			for _, lt := range decoded {
				switch lt {
				case layers.LayerTypeTCP:
					hasTCP = true
				case layers.LayerTypeUDP:
					hasUDP = true
				case layers.LayerTypeICMPv4:
					hasICMP = true
				case layers.LayerTypeIPv6:
					hasIPv6 = true
				case layers.LayerTypeICMPv6:
					hasICMPv6 = true
				}
			}

			if !hasTCP && !hasUDP && !hasICMP && !hasICMPv6 {
				continue
			}

			atomic.AddUint64(&recvPackets, 1)

			// ── TCP handling ───────────────────────────────────────
			if hasTCP {
				var myIP, targetIP stack.IPAddr
				var ttl uint8
				var remoteIPStr string
				if hasIPv6 {
					myIP = stack.IPAddr(targets.FromNetIP(ip6L.DstIP))
					targetIP = stack.IPAddr(targets.FromNetIP(ip6L.SrcIP))
					ttl = ip6L.HopLimit
					remoteIPStr = ip6L.SrcIP.String()
				} else {
					myIP = stack.IPAddr(targets.FromNetIP(ipL.DstIP))
					targetIP = stack.IPAddr(targets.FromNetIP(ipL.SrcIP))
					ttl = ipL.TTL
					remoteIPStr = ipL.SrcIP.String()
				}
				mySrcPort := uint16(tcpL.DstPort)
				remoteDstPort := uint16(tcpL.SrcPort)

				state, exists := connTable.Get(myIP, targetIP, mySrcPort, remoteDstPort)
				if !exists {
					if debug {
						atomic.AddUint64(&debugLookupMiss, 1)
						if n := atomic.LoadUint64(&debugLookupMiss); n <= 10 {
							fmt.Printf("\n[DBG] MISS: %s:%d->%s:%d flags=%s\n",
								remoteIPStr, remoteDstPort,
								stackIPToString(myIP), mySrcPort,
								tcpFlagStr(tcpL.SYN, tcpL.ACK, tcpL.RST, tcpL.FIN, tcpL.PSH))
						}
					}
				} else {
					if debug {
						atomic.AddUint64(&debugLookupHit, 1)
					}

					if engine != nil {
						if state.Status == stack.StatusSynSent && tcpL.SYN && tcpL.ACK {
							atomic.AddUint64(&foundOpen, 1)
							state.Seq = tcpL.Ack
							state.Ack = tcpL.Seq + 1

							fp := buildFingerprint(ttl, !hasIPv6 && ipL.Flags&layers.IPv4DontFragment != 0, &tcpL)
							guess := osfp.Classify(&fp)

							if engine.HandleSynAck(state, ttl) {
								logResult(sink, events, remoteIPStr, remoteDstPort, ttl, "", "OPEN", "", "tcp", *openOnlyFlag, &fp, &guess)
							} else {
								logResult(sink, events, remoteIPStr, remoteDstPort, ttl, "", "OPEN", "", "tcp", *openOnlyFlag, &fp, &guess)
								state.Status = stack.StatusClosed
							}
						} else if state.Status == stack.StatusEstablished {
							if tcpL.RST {
								engine.HandleRst(state, ttl)
							} else if tcpL.FIN {
								engine.HandleFin(state, tcpL.Seq, tcpL.Ack, ttl)
							} else if len(tcpL.Payload) > 0 {
								engine.HandleData(state, tcpL.Payload, tcpL.Seq, tcpL.Ack, ttl)
							}
						}
					} else {
						if state.Status == stack.StatusSynSent && tcpL.SYN && tcpL.ACK {
							atomic.AddUint64(&foundOpen, 1)

							fp := buildFingerprint(ttl, !hasIPv6 && ipL.Flags&layers.IPv4DontFragment != 0, &tcpL)
							guess := osfp.Classify(&fp)
							logResult(sink, events, remoteIPStr, remoteDstPort, ttl, "", "OPEN", "", "tcp", *openOnlyFlag, &fp, &guess)

							connTable.UpdateState(myIP, targetIP, mySrcPort, remoteDstPort,
								stack.StatusEstablished, tcpL.Ack, tcpL.Seq+1, nil)

							if legacyAckSender != nil {
								var ackDstIP net.IP
								if hasIPv6 {
									ackDstIP = ip6L.SrcIP
								} else {
									ackDstIP = ipL.SrcIP.To4()
								}
								legacyAckSender.SendACK(ackDstIP, int(remoteDstPort), int(mySrcPort), tcpL.Ack, tcpL.Seq+1)
							}
						} else if state.Status == stack.StatusEstablished && len(tcpL.Payload) > 0 {
							atomic.AddUint64(&bannerCount, 1)
							logResult(sink, events, remoteIPStr, remoteDstPort, ttl, string(tcpL.Payload), "BANNER", "", "tcp", *openOnlyFlag, nil, nil)
							connTable.UpdateState(myIP, targetIP, mySrcPort, remoteDstPort, stack.StatusClosed, 0, 0, nil)
						}
					}
				}
			}

			// ── UDP response handling ──────────────────────────────
			if hasUDP {
				var targetIP, myIP stack.IPAddr
				var ttl uint8
				var remoteIPStr string
				if hasIPv6 {
					targetIP = stack.IPAddr(targets.FromNetIP(ip6L.SrcIP))
					myIP = stack.IPAddr(targets.FromNetIP(ip6L.DstIP))
					ttl = ip6L.HopLimit
					remoteIPStr = ip6L.SrcIP.String()
				} else {
					targetIP = stack.IPAddr(targets.FromNetIP(ipL.SrcIP))
					myIP = stack.IPAddr(targets.FromNetIP(ipL.DstIP))
					ttl = ipL.TTL
					remoteIPStr = ipL.SrcIP.String()
				}
				mySrcPort := uint16(udpL.DstPort)
				remoteDstPort := uint16(udpL.SrcPort)

				state, exists := connTable.Get(myIP, targetIP, mySrcPort, remoteDstPort)
				if exists && state.Status == stack.StatusSynSent {
					atomic.AddUint64(&foundOpen, 1)
					bannerStr := string(udpL.Payload)
					probeName := ""
					if udpProbeTable != nil {
						if p := udpProbeTable.LookupPort(remoteDstPort); p != nil {
							probeName = p.Name
						}
					}
					logResult(sink, events, remoteIPStr, remoteDstPort, ttl, bannerStr, "OPEN", probeName, "udp", *openOnlyFlag, nil, nil)
					if len(bannerStr) > 0 {
						atomic.AddUint64(&bannerCount, 1)
						logResult(sink, events, remoteIPStr, remoteDstPort, ttl, bannerStr, "BANNER", probeName, "udp", *openOnlyFlag, nil, nil)
					}
					state.Status = stack.StatusClosed
					state.Updated = stack.NowNano()
				}
			}

			// ── ICMP Unreachable handling ──────────────────────────
			if hasICMP && icmpL.TypeCode.Type() == 3 {
				icmpPayload := icmpL.Payload
				if len(icmpPayload) >= 28 {
					var origSrcIPAddr, origDstIPAddr stack.IPAddr
					origSrcIPAddr[10], origSrcIPAddr[11] = 0xFF, 0xFF
					copy(origSrcIPAddr[12:16], icmpPayload[12:16])
					origDstIPAddr[10], origDstIPAddr[11] = 0xFF, 0xFF
					copy(origDstIPAddr[12:16], icmpPayload[16:20])
					origSrcPort := binary.BigEndian.Uint16(icmpPayload[20:22])
					origDstPort := binary.BigEndian.Uint16(icmpPayload[22:24])

					state, exists := connTable.Get(origSrcIPAddr, origDstIPAddr, origSrcPort, origDstPort)
					if exists && state.Status == stack.StatusSynSent {
						state.Status = stack.StatusClosed
						state.Updated = stack.NowNano()
					}
				}
			}

			// ── ICMPv6 Destination Unreachable (type 1) ──────────
			if hasICMPv6 && icmp6L.TypeCode.Type() == 1 {
				// Payload: original IPv6 header (40 bytes) + transport header (8+ bytes)
				icmp6Payload := icmp6L.Payload
				if len(icmp6Payload) >= 48 {
					var origSrcIPAddr, origDstIPAddr stack.IPAddr
					copy(origSrcIPAddr[:], icmp6Payload[8:24])
					copy(origDstIPAddr[:], icmp6Payload[24:40])
					origSrcPort := binary.BigEndian.Uint16(icmp6Payload[40:42])
					origDstPort := binary.BigEndian.Uint16(icmp6Payload[42:44])

					state, exists := connTable.Get(origSrcIPAddr, origDstIPAddr, origSrcPort, origDstPort)
					if exists && state.Status == stack.StatusSynSent {
						state.Status = stack.StatusClosed
						state.Updated = stack.NowNano()
					}
				}
			}
		}
	}()

	// ── Sharded Senders ────────────────────────────────────────────────
	numShards := *shardsFlag
	totalPPS := float64(*ppsFlag)

	// Count total iterators to split PPS budget
	numIters := 0
	if tcpIter != nil {
		numIters++
	}
	if udpIter != nil {
		numIters++
	}
	if numIters == 0 {
		log.Fatal("no scan targets (no matching ports for scan mode)")
	}

	shardPPSEach := totalPPS / float64(numShards*numIters)

	// Total search space for progress tracking
	var totalSpace uint64
	if tcpIter != nil {
		totalSpace += getTotalSize(tcpIter)
	}
	if udpIter != nil {
		totalSpace += getTotalSize(udpIter)
	}

	shardSent := make([]uint64, numShards*numIters)
	var wg sync.WaitGroup
	start := time.Now()

	// TCP sender shards — uses TX_RING (mmap'd AF_PACKET) for high throughput.
	// Each shard gets its own ring. QueueSYN patches frames in mmap, Flush()
	// does a single sendto() to kick the entire batch — ~2x faster than
	// per-packet write() syscalls.
	if tcpIter != nil {
		tcpShards := tcpIter.Split(numShards)
		for i := 0; i < numShards; i++ {
			wg.Add(1)
			go func(shardIdx int, it *targets.TupleIterator) {
				defer wg.Done()

				var seed uint64
				binary.Read(rand.Reader, binary.LittleEndian, &seed)
				lim := limiter.NewTokenBucket(shardPPSEach, shardPPSEach/10)

				var localSent uint64
				defer func() { atomic.StoreUint64(&shardSent[shardIdx], localSent) }()

				// Skip TX_RING for TUN interfaces — AF_PACKET injection fails on
				// GRE/SIT/IPIP tunnels; tunnelWriter (raw socket) is needed instead.
				var ts *sender.TXRingSender
				var txErr error
				if !isTUN {
					ts, txErr = sender.NewTXRingSender(*iface, sMAC, dMAC, sIP)
				} else {
					txErr = fmt.Errorf("TUN mode")
				}
				if txErr != nil {
					log.Printf("tcp shard %d: TX_RING failed (%v), falling back to write()", shardIdx, txErr)
					// Fallback to per-packet write()
					s, err2 := sender.NewRingSender(*iface, sMAC, dMAC, sIP)
					if err2 != nil {
						log.Printf("tcp shard %d: fallback also failed: %v", shardIdx, err2)
						return
					}
					if hasIPv6Source {
						s.ConfigureIPv6(srcIPv6Bytes, sMAC, gwMACv6)
					}
					for atomic.LoadInt32(&running) == 1 {
						lim.Wait(100)
						for k := 0; k < 100; k++ {
							tIP, tPort, ok := it.Next()
							if !ok {
								return
							}
							seed ^= seed << 13
							seed ^= seed >> 7
							seed ^= seed << 17
							srcPort := uint16(32768 + seed%17232)
							seq := s.GenerateCookie([16]byte(tIP), tPort)
							myIP := srcIPAddr
							if !tIP.IsIPv4() {
								myIP = srcIPv6Addr
							}
							connTable.AddSynSent(stack.IPAddr(myIP), stack.IPAddr(tIP), srcPort, tPort, seq)
							s.SendSYNWithPort([16]byte(tIP), tPort, srcPort)
							localSent++
						}
						atomic.StoreUint64(&shardSent[shardIdx], localSent)
					}
					return
				}
				if hasIPv6Source {
					ts.ConfigureIPv6(srcIPv6Bytes, sMAC, gwMACv6)
				}
				defer ts.Close()

				for atomic.LoadInt32(&running) == 1 {
					lim.Wait(sender.BatchSize)
					for k := 0; k < sender.BatchSize; k++ {
						tIP, tPort, ok := it.Next()
						if !ok {
							if ts.Pending() > 0 {
								ts.Flush()
							}
							return
						}
						seed ^= seed << 13
						seed ^= seed >> 7
						seed ^= seed << 17
						srcPort := uint16(32768 + seed%17232) // TCP: 32768-49999

						seq := ts.GenerateCookie([16]byte(tIP), tPort)
						myIP := srcIPAddr
						if !tIP.IsIPv4() {
							myIP = srcIPv6Addr
						}
						connTable.AddSynSent(stack.IPAddr(myIP), stack.IPAddr(tIP), srcPort, tPort, seq)
						if ts.QueueSYN([16]byte(tIP), tPort, srcPort) {
							ts.Flush()
						}
						localSent++
					}
					if ts.Pending() > 0 {
						ts.Flush()
					}
					atomic.StoreUint64(&shardSent[shardIdx], localSent)
				}
			}(i, tcpShards[i])
		}
	}

	// UDP sender shards
	if udpIter != nil {
		udpShards := udpIter.Split(numShards)
		baseIdx := numShards // offset into shardSent for UDP shards
		if tcpIter == nil {
			baseIdx = 0
		}
		for i := 0; i < numShards; i++ {
			wg.Add(1)
			go func(shardIdx int, it *targets.TupleIterator) {
				defer wg.Done()
				s, err := sender.NewRingSender(*iface, sMAC, dMAC, sIP)
				if err != nil {
					log.Printf("udp shard %d: failed to create sender: %v", shardIdx, err)
					return
				}
				if hasIPv6Source {
					s.ConfigureIPv6(srcIPv6Bytes, sMAC, gwMACv6)
				}
				lim := limiter.NewTokenBucket(shardPPSEach, shardPPSEach/10)

				var seed uint64
				binary.Read(rand.Reader, binary.LittleEndian, &seed)

				var localSent uint64
				defer func() { atomic.StoreUint64(&shardSent[baseIdx+shardIdx], localSent) }()
				for atomic.LoadInt32(&running) == 1 {
					lim.Wait(100)
					for k := 0; k < 100; k++ {
						tIP, tPort, ok := it.Next()
						if !ok {
							return
						}
						seed ^= seed << 13
						seed ^= seed >> 7
						seed ^= seed << 17
						srcPort := uint16(50000 + seed%10999) // UDP: 50000-60999

						var payload []byte
						if udpProbeTable != nil {
							probe := udpProbeTable.LookupPort(tPort)
							if probe != nil && probe.Hello != nil {
								payload = probe.Hello
							}
						}

						myIP := srcIPAddr
						if !tIP.IsIPv4() {
							myIP = srcIPv6Addr
						}
						connTable.AddSynSent(stack.IPAddr(myIP), stack.IPAddr(tIP), srcPort, tPort, 0)
						s.SendUDP([16]byte(tIP), tPort, srcPort, payload)
						localSent++
					}
					atomic.StoreUint64(&shardSent[baseIdx+shardIdx], localSent)
				}
			}(i, udpShards[i])
		}
	}

	// ── Management Loop ────────────────────────────────────────────────
	sendersDone := make(chan struct{})
	go func() { wg.Wait(); close(sendersDone) }()
	ticker := time.NewTicker(1 * time.Second)
	var phase1Ticker *time.Ticker
	if engine != nil {
		phase1Ticker = time.NewTicker(100 * time.Millisecond)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	var phase1Chan <-chan time.Time
	if phase1Ticker != nil {
		phase1Chan = phase1Ticker.C
	}
	var drainTimer <-chan time.Time

	// Retransmit support for UDP
	retries := *retriesFlag
	var retransmitTicker *time.Ticker
	var retransmitChan <-chan time.Time
	var retransmitSender *sender.RingSender
	if doUDP && retries > 0 {
		retransmitTicker = time.NewTicker(1 * time.Second)
		retransmitChan = retransmitTicker.C
		retransmitSender, err = sender.NewRingSender(*iface, sMAC, dMAC, sIP)
		if err != nil {
			log.Printf("warning: failed to create retransmit sender: %v (UDP retransmits disabled)", err)
			retransmitTicker.Stop()
			retransmitTicker = nil
			retransmitChan = nil
		} else if hasIPv6Source {
			retransmitSender.ConfigureIPv6(srcIPv6Bytes, sMAC, gwMACv6)
		}
	}

	// Helper to aggregate stats
	collectStats := func() ui.ScanStats {
		var totalSentAgg uint64
		for i := range shardSent {
			totalSentAgg += atomic.LoadUint64(&shardSent[i])
		}
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()
		rate := float64(0)
		if elapsedSec > 0 {
			rate = float64(totalSentAgg) / elapsedSec
		}
		progress := float64(0)
		if totalSpace > 0 {
			progress = float64(totalSentAgg) / float64(totalSpace)
			if progress > 1 {
				progress = 1
			}
		}
		_, drops := recv.SocketStats()
		return ui.ScanStats{
			Sent:     totalSentAgg,
			Recv:     atomic.LoadUint64(&recvPackets),
			Open:     atomic.LoadUint64(&foundOpen),
			Banners:  atomic.LoadUint64(&bannerCount),
			Drops:    drops,
			Elapsed:  elapsed,
			Progress: progress,
			Rate:     rate,
		}
	}

	// ── Start UI ───────────────────────────────────────────────────────
	var program *tea.Program
	var textPrinter *ui.TextPrinter

	switch uiMode {
	case ui.ModeTUI:
		model := ui.NewModel(
			strings.Join(targetList, ","),
			*portFlag,
			*iface,
			scanModeStr,
			&running,
		)
		program = tea.NewProgram(model, tea.WithAltScreen())

		// Feed events to bubbletea
		go func() {
			for ev := range events {
				program.Send(ev)
			}
		}()

		// Stats ticker → bubbletea
		go func() {
			statsTicker := time.NewTicker(250 * time.Millisecond)
			defer statsTicker.Stop()
			for range statsTicker.C {
				if atomic.LoadInt32(&running) != 1 {
					return
				}
				program.Send(collectStats())
			}
		}()

	case ui.ModeText:
		textOut := io.Writer(os.Stdout)
		if stdoutOutput {
			textOut = os.Stderr
		}
		textPrinter = &ui.TextPrinter{Verbose: *verboseFlag, Out: textOut}
		go func() {
			for ev := range events {
				textPrinter.PrintEvent(ev)
			}
		}()

	case ui.ModeSilent:
		go func() {
			for range events {
			}
		}()
	}

	// ── Management select loop (runs in background for TUI mode) ──────
	managementDone := make(chan struct{})
	go func() {
		defer close(managementDone)
		for {
			select {
			case <-sigs:
				emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: "\nAborted."})
				atomic.StoreInt32(&running, 0)
				return
			case <-sendersDone:
				emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: "Sending complete. Waiting for responses..."})
				drainTimer = time.After(*timeoutFlag)
				sendersDone = nil
			case <-drainTimer:
				return
			case <-phase1Chan:
				engine.CheckPhase1()
			case <-retransmitChan:
				// UDP retransmit: sweep SynSent entries in UDP port range and resend probes
				connTable.SweepRetransmit(50000, 60999, uint8(retries), func(st *stack.State) {
					var payload []byte
					if udpProbeTable != nil {
						if p := udpProbeTable.LookupPort(st.DstPort); p != nil && p.Hello != nil {
							payload = p.Hello
						}
					}
					retransmitSender.SendUDP([16]byte(st.DstIP), st.DstPort, st.SrcPort, payload)
				})
			case <-ticker.C:
				expired := connTable.Cleanup(*timeoutFlag)

				if engine != nil {
					engine.CheckTimers(expired)
				}

				if *verboseFlag && !*openOnlyFlag {
					for _, st := range expired {
						if st.Status == stack.StatusSynSent {
							proto := "tcp"
							if st.SrcPort >= 50000 && st.SrcPort <= 60999 {
								proto = "udp"
							}
							logResult(sink, events, stackIPToString(st.DstIP), st.DstPort, 0, "", "TIMEOUT", "", proto, *openOnlyFlag, nil, nil)
						}
					}
				}

				stack.ReleaseExpired(expired)

				// Print stats in text mode
				if uiMode == ui.ModeText {
					textPrinter.PrintStats(collectStats())
				}
			}
		}
	}()

	// ── Run (TUI blocks, text/silent wait for management) ──────────────
	if uiMode == ui.ModeTUI {
		// Management loop runs in background; TUI blocks here
		go func() {
			<-managementDone
			// Scan finished — tell TUI to quit
			emitEvent(ui.ScanEvent{Type: ui.EvtDone})
		}()
		if _, err := program.Run(); err != nil {
			log.Fatal(err)
		}
		atomic.StoreInt32(&running, 0)
	} else {
		<-managementDone
	}

	// ── Cleanup ────────────────────────────────────────────────────────
	atomic.StoreInt32(&running, 0)
	signal.Stop(sigs)

	<-recvDone

	recv.Close()
	if legacyAckSender != nil {
		legacyAckSender.Close()
	}
	if responder != nil {
		responder.Close()
	}
	if grabOutput != nil {
		close(grabOutput)
		<-grabDone // wait for goroutine to drain all results before closing sink
	}
	if phase1Ticker != nil {
		phase1Ticker.Stop()
	}
	if retransmitTicker != nil {
		retransmitTicker.Stop()
	}
	if retransmitSender != nil {
		retransmitSender.Close()
	}
	sink.Close()
	close(events)

	// Final stats
	stats := collectStats()
	statsDest := os.Stdout
	if stdoutOutput {
		statsDest = os.Stderr
	}
	fmt.Fprintf(statsDest, "\nScan finished. Sent: %d, Open: %d, Banners: %d\n",
		stats.Sent, stats.Open, stats.Banners)
}

// ── Helpers ────────────────────────────────────────────────────────────

func tcpFlagStr(syn, ack, rst, fin, psh bool) string {
	s := ""
	if syn {
		s += "S"
	}
	if ack {
		s += "A"
	}
	if rst {
		s += "R"
	}
	if fin {
		s += "F"
	}
	if psh {
		s += "P"
	}
	if s == "" {
		s = "."
	}
	return s
}

func stackIPToString(ip stack.IPAddr) string {
	if ip[10] == 0xFF && ip[11] == 0xFF {
		return fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	}
	return net.IP(ip[:]).String()
}

func logResult(sink *output.OutputSink, events chan<- ui.ScanEvent, ip string, port uint16, ttl uint8, bannerStr string, event string, probe string, proto string, openOnly bool, fp *osfp.TCPFingerprint, guess *osfp.OSGuess) {
	if openOnly && event == "TIMEOUT" {
		return
	}

	res := &output.Result{
		Event:     event,
		IP:        ip,
		Port:      port,
		Proto:     proto,
		Timestamp: time.Now().Format(time.RFC3339),
		TTL:       ttl,
		Banner:    bannerStr,
	}
	if fp != nil {
		res.Window = fp.Window
		res.MSS = fp.MSS
		res.WScale = fp.WScale
		res.TCPOptions = fp.OptOrder.String()
		res.DF = fp.DF
	}
	var osFamily, osConf string
	if guess != nil && guess.Confidence > osfp.ConfNone {
		osFamily = guess.Family
		osConf = guess.Confidence.String()
		res.OSFamily = osFamily
		res.OSConfidence = osConf
	}
	sink.Write(res)

	var evType ui.EventType
	switch event {
	case "OPEN":
		evType = ui.EvtOpen
	case "BANNER":
		evType = ui.EvtBanner
	case "TIMEOUT":
		evType = ui.EvtTimeout
	default:
		return
	}

	select {
	case events <- ui.ScanEvent{
		Type:         evType,
		IP:           ip,
		Port:         port,
		Proto:        proto,
		TTL:          ttl,
		Banner:       bannerStr,
		Probe:        probe,
		OSFamily:     osFamily,
		OSConfidence: osConf,
	}:
	default:
	}
}

// buildFingerprint captures TCP/IP fingerprint signals from a SYN-ACK.
// For IPv6, df should be true (IPv6 doesn't fragment in transit).
func buildFingerprint(ttl uint8, df bool, tcpL *layers.TCP) osfp.TCPFingerprint {
	fp := osfp.TCPFingerprint{
		TTL:    ttl,
		DF:     df,
		Window: tcpL.Window,
		WScale: 0xFF, // sentinel: absent
		ECE:    tcpL.ECE,
		CWR:    tcpL.CWR,
	}

	var kindBuf [osfp.MaxOpts]uint8
	nKinds := 0
	for _, opt := range tcpL.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				fp.MSS = uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				fp.WScale = opt.OptionData[0]
			}
		case layers.TCPOptionKindSACKPermitted:
			fp.SACKPerm = true
		case layers.TCPOptionKindTimestamps:
			fp.Timestamps = true
		}
		if nKinds < osfp.MaxOpts {
			kindBuf[nKinds] = uint8(opt.OptionType)
			nKinds++
		}
	}
	fp.OptOrder = osfp.EncodeOptOrder(kindBuf[:nKinds])

	return fp
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func portsToString(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}

// getTotalSize extracts the total search space from a TupleIterator.
// We split and sum to find the end boundary.
func getTotalSize(it *targets.TupleIterator) uint64 {
	// The iterator starts at current=0, end=totalSize.
	// We can use Split(1) to get a clone that has end set to totalSize.
	shards := it.Split(1)
	// After split, our iterator is consumed. But Split clones, so the original
	// was already cloned. Actually Split modifies nothing — it creates copies.
	// The single shard will have end = totalSize.
	return shards[0].GetEnd()
}

// applyConfig applies config values for flags that were not explicitly set on the CLI.
func applyConfig(cfg *config.Config, set map[string]bool,
	iface, portFlag *string, ppsFlag, shardsFlag *int,
	timeoutFlag *time.Duration, retriesFlag, arenaSlots *int,
	sourceIPFlag, gwMACFlag, probeDir *string,
	outputFile, oG, webhookURL *string,
	bannerGrabFlag, sequentialFlag, openOnlyFlag, verboseFlag, debugFlag, quietFlag, noTUI *bool,
	scanSS, scanSU *bool,
) {
	s := cfg.Scan
	o := cfg.Output

	if !set["i"] && !set["e"] && s.Interface != "" {
		*iface = s.Interface
	}
	if !set["p"] && s.Ports != "" {
		*portFlag = s.Ports
	}
	if !set["pps"] && !set["rate"] && s.Rate > 0 {
		*ppsFlag = s.Rate
	}
	if !set["shards"] && s.Shards > 0 {
		*shardsFlag = s.Shards
	}
	if !set["timeout"] && !set["wait"] && s.Timeout.Duration > 0 {
		*timeoutFlag = s.Timeout.Duration
	}
	if !set["retries"] && s.Retries > 0 {
		*retriesFlag = s.Retries
	}
	if !set["arena-slots"] && s.ArenaSlots > 0 {
		*arenaSlots = s.ArenaSlots
	}
	if !set["S"] && s.SourceIP != "" {
		*sourceIPFlag = s.SourceIP
	}
	if !set["gw-mac"] && s.GwMAC != "" {
		*gwMACFlag = s.GwMAC
	}
	if !set["probes"] && s.Probes != "" {
		*probeDir = s.Probes
	}
	if !set["banner-grab"] && !set["banners"] && s.BannerGrab {
		*bannerGrabFlag = true
	}
	if !set["sequential"] && s.Sequential {
		*sequentialFlag = true
	}

	// Scan mode from config
	if !set["sS"] && !set["sU"] && s.Mode != "" {
		switch strings.ToLower(s.Mode) {
		case "syn":
			*scanSS = true
		case "udp":
			*scanSU = true
		case "both":
			*scanSS = true
			*scanSU = true
		}
	}

	// Output
	if !set["o"] && !set["oJ"] && o.File != "" {
		*outputFile = o.File
	}
	if !set["oG"] && o.Grepable != "" {
		*oG = o.Grepable
	}
	if !set["webhook"] && o.Webhook != nil && o.Webhook.URL != "" {
		*webhookURL = o.Webhook.URL
	}
	if !set["open"] && o.OpenOnly {
		*openOnlyFlag = true
	}
	if !set["v"] && o.Verbose {
		*verboseFlag = true
	}
	if !set["debug"] && o.Debug {
		*debugFlag = true
	}
	if !set["q"] && !set["quiet"] && o.Quiet {
		*quietFlag = true
	}
	if !set["no-tui"] && o.NoTUI {
		*noTUI = true
	}
}
