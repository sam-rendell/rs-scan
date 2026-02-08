package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"rs_scan/internal/banner"
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

	// Sequential mode
	sequentialFlag := flag.Bool("sequential", false, "Scan targets in order (no randomization)")

	// Output filtering
	openOnlyFlag := flag.Bool("open", false, "Only log open/banner results")

	// UI mode flags
	quietFlag := flag.Bool("q", false, "Silent mode (no terminal output)")
	quietAlias := flag.Bool("quiet", false, "Silent mode (alias for -q)")
	noTUI := flag.Bool("no-tui", false, "Disable TUI (text mode)")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("rs_scan version %s\n", version.Version)
		return
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
		log.Fatal("no targets specified (use -t, positional args, or -iL)")
	}

	// ── Build exclusion list ───────────────────────────────────────────
	var excludeList []string
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

	// ── Build iterators ────────────────────────────────────────────────
	var tcpIter *targets.TupleIterator
	var udpIter *targets.TupleIterator

	if doTCP && len(tcpPorts) > 0 {
		portStr := portsToString(tcpPorts)
		tcpIter, err = targets.NewTupleIterator(targetList, portStr, excludeList, *sequentialFlag)
		if err != nil {
			log.Fatalf("TCP iterator: %v", err)
		}
	}
	if doUDP && len(udpPorts) > 0 {
		portStr := portsToString(udpPorts)
		udpIter, err = targets.NewTupleIterator(targetList, portStr, excludeList, *sequentialFlag)
		if err != nil {
			log.Fatalf("UDP iterator: %v", err)
		}
	}

	// ── Network Discovery ──────────────────────────────────────────────
	details, err := netinfo.GetDetails(*iface)
	if err != nil {
		log.Fatal(err)
	}
	sIP, sMAC, dMAC := details.SrcIP, details.SrcMAC, details.GatewayMAC
	srcIPu32 := targets.IPToUint32(sIP)

	// ── Components ─────────────────────────────────────────────────────
	connTable := stack.NewConnectionTable()

	// Output sink: fan out to multiple writers
	sink := output.NewOutputSink()

	outWriter, err := output.NewWriter(*outputFile)
	if err != nil {
		log.Fatalf("failed to open output file: %v", err)
	}
	sink.Add(outWriter)

	// Grepable output
	var grepFile *os.File
	if *oG != "" {
		grepFile, err = os.OpenFile(*oG, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open grepable output file: %v", err)
		}
		grepFmt := output.NewGrepFormatter(grepFile)
		sink.Add(&output.MultiWriter{Formatter: grepFmt})
	}

	recv, err := receiver.NewListener(*iface)
	if err != nil {
		log.Fatal(err)
	}

	// ── BPF filter based on scan mode ──────────────────────────────────
	var bpfFilter string
	switch {
	case doTCP && doUDP:
		bpfFilter = fmt.Sprintf("(tcp or udp or (icmp and icmp[icmptype]==3)) and dst host %s", sIP.String())
	case doUDP:
		bpfFilter = fmt.Sprintf("(udp or (icmp and icmp[icmptype]==3)) and dst host %s", sIP.String())
	default:
		bpfFilter = fmt.Sprintf("tcp and dst host %s", sIP.String())
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
	var bannerCount uint64

	// Load UDP probe table (for UDP sender payloads)
	var udpProbeTable *banner.ProbeTable
	if doUDP {
		udpProbeTable = banner.NewProbeTable()
		pDir := *probeDir
		if pDir == "" {
			exe, _ := os.Executable()
			pDir = filepath.Join(filepath.Dir(exe), "probes", "udp")
			if _, err := os.Stat(pDir); os.IsNotExist(err) {
				pDir = filepath.Join("probes", "udp")
			}
		} else {
			// If user specified a dir, look for udp subdir
			udpDir := filepath.Join(pDir, "udp")
			if _, err := os.Stat(udpDir); err == nil {
				pDir = udpDir
			}
		}
		if err := udpProbeTable.LoadProbes(pDir); err != nil {
			log.Printf("warning: failed to load UDP probes from %s: %v", pDir, err)
		} else {
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Loaded %d UDP probes from %s", len(udpProbeTable.Probes), pDir)})
		}
	}

	if *bannerGrabFlag && doTCP {
		pDir := *probeDir
		if pDir == "" {
			exe, _ := os.Executable()
			pDir = filepath.Join(filepath.Dir(exe), "probes", "tcp")
			if _, err := os.Stat(pDir); os.IsNotExist(err) {
				pDir = filepath.Join("probes", "tcp")
			}
		}

		probeTable := banner.NewProbeTable()
		if err := probeTable.LoadProbes(pDir); err != nil {
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
			SrcIP:       srcIPu32,
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

		go func() {
			for gr := range grabOutput {
				atomic.AddUint64(&bannerCount, 1)
				ip := targets.Uint32ToIP(gr.IP).String()
				logResult(sink, events, ip, gr.Port, gr.TTL, string(gr.Banner), "BANNER", gr.Probe, "tcp", *openOnlyFlag, nil, nil)
			}
		}()

		rstCheck := exec.Command("iptables", "-C", "OUTPUT",
			"-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		if err := rstCheck.Run(); err != nil {
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: "WARNING: no iptables RST suppression — banner grabs will be unreliable"})
			emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: "  run: iptables -I OUTPUT 1 -p tcp --sport 32768:60999 --tcp-flags RST RST -j DROP"})
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
	}

	emitEvent(ui.ScanEvent{Type: ui.EvtInfo, Msg: fmt.Sprintf("Source: %s (%s), Gateway: %s", sIP, sMAC, dMAC)})
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
	var ipL layers.IPv4
	var tcpL layers.TCP
	var udpL layers.UDP
	var icmpL layers.ICMPv4
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&ethL, &ipL, &tcpL, &udpL, &icmpL)
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 0, 6)
	recvDone := make(chan struct{})

	go func() {
		defer close(recvDone)
		for atomic.LoadInt32(&running) == 1 {
			data, _, err := recv.Handle.ZeroCopyReadPacketData()
			if err != nil {
				continue
			}

			if err := parser.DecodeLayers(data, &decoded); err != nil {
				continue
			}

			hasTCP, hasUDP, hasICMP := false, false, false
			for _, lt := range decoded {
				switch lt {
				case layers.LayerTypeTCP:
					hasTCP = true
				case layers.LayerTypeUDP:
					hasUDP = true
				case layers.LayerTypeICMPv4:
					hasICMP = true
				}
			}

			if !hasTCP && !hasUDP && !hasICMP {
				continue
			}

			atomic.AddUint64(&recvPackets, 1)

			// ── TCP handling ───────────────────────────────────────
			if hasTCP {
				myIP := targets.IPToUint32(ipL.DstIP)
				targetIP := targets.IPToUint32(ipL.SrcIP)
				mySrcPort := uint16(tcpL.DstPort)
				remoteDstPort := uint16(tcpL.SrcPort)

				state, exists := connTable.Get(myIP, targetIP, mySrcPort, remoteDstPort)
				if !exists {
					if debug {
						atomic.AddUint64(&debugLookupMiss, 1)
						if n := atomic.LoadUint64(&debugLookupMiss); n <= 10 {
							fmt.Printf("\n[DBG] MISS: %s:%d->%s:%d flags=%s\n",
								targets.Uint32ToIP(targetIP), remoteDstPort,
								targets.Uint32ToIP(myIP), mySrcPort,
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

							fp := extractFingerprint(&ipL, &tcpL)
							guess := osfp.Classify(&fp)

							if engine.HandleSynAck(state, ipL.TTL) {
								logResult(sink, events, ipL.SrcIP.String(), remoteDstPort, ipL.TTL, "", "OPEN", "", "tcp", *openOnlyFlag, &fp, &guess)
							} else {
								logResult(sink, events, ipL.SrcIP.String(), remoteDstPort, ipL.TTL, "", "OPEN", "", "tcp", *openOnlyFlag, &fp, &guess)
								state.Status = stack.StatusClosed
							}
						} else if state.Status == stack.StatusEstablished {
							if tcpL.RST {
								engine.HandleRst(state, ipL.TTL)
							} else if tcpL.FIN {
								engine.HandleFin(state, tcpL.Seq, tcpL.Ack, ipL.TTL)
							} else if len(tcpL.Payload) > 0 {
								engine.HandleData(state, tcpL.Payload, tcpL.Seq, tcpL.Ack, ipL.TTL)
							}
						}
					} else {
						if state.Status == stack.StatusSynSent && tcpL.SYN && tcpL.ACK {
							atomic.AddUint64(&foundOpen, 1)

							fp := extractFingerprint(&ipL, &tcpL)
							guess := osfp.Classify(&fp)
							logResult(sink, events, ipL.SrcIP.String(), remoteDstPort, ipL.TTL, "", "OPEN", "", "tcp", *openOnlyFlag, &fp, &guess)

							connTable.UpdateState(myIP, targetIP, mySrcPort, remoteDstPort,
								stack.StatusEstablished, tcpL.Ack, tcpL.Seq+1, nil)

							if legacyAckSender != nil {
								legacyAckSender.SendACK(ipL.SrcIP, int(remoteDstPort), int(mySrcPort), tcpL.Ack, tcpL.Seq+1)
							}
						} else if state.Status == stack.StatusEstablished && len(tcpL.Payload) > 0 {
							atomic.AddUint64(&bannerCount, 1)
							logResult(sink, events, ipL.SrcIP.String(), remoteDstPort, ipL.TTL, string(tcpL.Payload), "BANNER", "", "tcp", *openOnlyFlag, nil, nil)
							connTable.UpdateState(myIP, targetIP, mySrcPort, remoteDstPort, stack.StatusClosed, 0, 0, nil)
						}
					}
				}
			}

			// ── UDP response handling ──────────────────────────────
			if hasUDP {
				targetIP := targets.IPToUint32(ipL.SrcIP)
				myIP := targets.IPToUint32(ipL.DstIP)
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
					logResult(sink, events, ipL.SrcIP.String(), remoteDstPort, ipL.TTL, bannerStr, "OPEN", probeName, "udp", *openOnlyFlag, nil, nil)
					if len(bannerStr) > 0 {
						atomic.AddUint64(&bannerCount, 1)
						logResult(sink, events, ipL.SrcIP.String(), remoteDstPort, ipL.TTL, bannerStr, "BANNER", probeName, "udp", *openOnlyFlag, nil, nil)
					}
					state.Status = stack.StatusClosed
					state.Updated = stack.NowNano()
				}
			}

			// ── ICMP Unreachable handling ──────────────────────────
			if hasICMP && icmpL.TypeCode.Type() == 3 {
				icmpPayload := icmpL.Payload
				if len(icmpPayload) >= 28 {
					origSrcIP := binary.BigEndian.Uint32(icmpPayload[12:16])
					origDstIP := binary.BigEndian.Uint32(icmpPayload[16:20])
					origSrcPort := binary.BigEndian.Uint16(icmpPayload[20:22])
					origDstPort := binary.BigEndian.Uint16(icmpPayload[22:24])

					state, exists := connTable.Get(origSrcIP, origDstIP, origSrcPort, origDstPort)
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
		totalSpace += tcpIter.GetState() // end is stored differently; use totalSize
	}
	if udpIter != nil {
		totalSpace += udpIter.GetState()
	}
	// Actually GetState() returns current (0), we need total. Use a helper.
	totalSpace = 0
	if tcpIter != nil {
		totalSpace += getTotalSize(tcpIter)
	}
	if udpIter != nil {
		totalSpace += getTotalSize(udpIter)
	}

	shardSent := make([]uint64, numShards*numIters)
	var wg sync.WaitGroup
	start := time.Now()

	// TCP sender shards
	if tcpIter != nil {
		tcpShards := tcpIter.Split(numShards)
		for i := 0; i < numShards; i++ {
			wg.Add(1)
			go func(shardIdx int, it *targets.TupleIterator) {
				defer wg.Done()
				s, err := sender.NewRingSender(*iface, sMAC, dMAC, sIP)
				if err != nil {
					log.Printf("tcp shard %d: failed to create sender: %v", shardIdx, err)
					return
				}
				lim := limiter.NewTokenBucket(shardPPSEach, shardPPSEach/10)

				var seed uint64
				binary.Read(rand.Reader, binary.LittleEndian, &seed)

				var localSent uint64
				defer func() { atomic.StoreUint64(&shardSent[shardIdx], localSent) }()
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
						srcPort := uint16(32768 + seed%17232) // TCP: 32768-49999

						seq := s.GenerateCookie(tIP, tPort)
						connTable.AddSynSent(srcIPu32, tIP, srcPort, tPort, seq)
						s.SendSYNWithPort(tIP, tPort, srcPort)
						localSent++
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

						connTable.AddSynSent(srcIPu32, tIP, srcPort, tPort, 0)
						s.SendUDP(tIP, tPort, srcPort, payload)
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
		textPrinter = &ui.TextPrinter{Verbose: *verboseFlag}
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
					retransmitSender.SendUDP(st.DstIP, st.DstPort, st.SrcPort, payload)
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
							logResult(sink, events, targets.Uint32ToIP(st.DstIP).String(), st.DstPort, 0, "", "TIMEOUT", "", proto, *openOnlyFlag, nil, nil)
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
	outWriter.Close()
	if grepFile != nil {
		grepFile.Close()
	}
	close(events)

	// Final stats
	stats := collectStats()
	fmt.Printf("\nScan finished. Sent: %d, Open: %d, Banners: %d\n",
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

// extractFingerprint captures TCP/IP fingerprint signals from SYN-ACK.
func extractFingerprint(ipL *layers.IPv4, tcpL *layers.TCP) osfp.TCPFingerprint {
	fp := osfp.TCPFingerprint{
		TTL:    ipL.TTL,
		DF:     ipL.Flags&layers.IPv4DontFragment != 0,
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
