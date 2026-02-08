package ui

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const maxRows = 10000

// Filter presets
const (
	FilterAll    = 0
	FilterOpen   = 1
	FilterBanner = 2
)

// resultRow is a single deduplicated scan result keyed by ip:port/proto.
type resultRow struct {
	IP      string
	Port    uint16
	Proto   string
	TTL     uint8
	Service string // probe name
	Banner  string // raw banner bytes as string
	State   string // "open", "banner", "timeout"
	Time    time.Time
	seq     int // insertion order
}

func rowKey(ip string, port uint16, proto string) string {
	return fmt.Sprintf("%s:%d/%s", ip, port, proto)
}

// Model is the bubbletea TUI model.
type Model struct {
	// Config
	Target   string
	PortSpec string
	Iface    string
	ScanMode string

	// Data
	rows    map[string]*resultRow // keyed by ip:port/proto
	order   []string              // keys in insertion order
	nextSeq int

	// Stats
	stats ScanStats

	// Cumulative counters (survive eviction)
	totalAll    uint64 // unique ip:port/proto ever seen
	totalOpen   uint64 // open or banner state
	totalBanner uint64 // banner only

	// Port histogram
	portCounts   map[uint16]uint64 // port -> count of opens
	topPorts     []portCount       // sorted top-10
	topPortsDirty bool

	// Discovery sparkline
	sparkBuf     [60]uint64 // ring buffer: opens per second
	sparkIdx     int        // next write index
	sparkPrev    uint64     // previous totalOpen snapshot
	sparkFilled  int        // how many slots are filled

	// Tree view
	treeMode   bool
	subnets    []*subnetNode
	subnetMap  map[uint32]*subnetNode
	treeCursor int
	treeOffset int

	// Heatmap view
	heatmapMode bool

	// View state
	cursor     int  // index into filtered view
	offset     int  // scroll offset
	follow     bool // auto-follow new results
	filterMode int  // FilterAll, FilterOpen, FilterBanner
	searching  bool // typing in search box
	searchText string
	filtered   []*resultRow // cached filtered+sorted view

	// Terminal
	width, height int
	done          bool
	quitting      bool

	Running *int32
}

// portCount tracks a port and its open count for the histogram.
type portCount struct {
	Port  uint16
	Count uint64
}

// ── Tree view types ──────────────────────────────────────────────────

type portEntry struct {
	Port    uint16
	Proto   string
	Service string
	Banner  string
	TTL     uint8
	State   string // "open" or "banner"
}

type hostNode struct {
	IP       uint32
	IPStr    string
	Ports    []*portEntry
	Expanded bool
	OSFamily string // best OS guess for this host
	OSConf   string // confidence level
}

type subnetNode struct {
	Prefix   uint32 // /24 network address (IP & 0xFFFFFF00)
	Label    string // "192.168.1.0/24"
	Hosts    []*hostNode
	HostMap  map[uint32]*hostNode
	Expanded bool
	Count    int // total port count
}

func NewModel(target, portSpec, iface, scanMode string, running *int32) Model {
	return Model{
		Target:     target,
		PortSpec:   portSpec,
		Iface:      iface,
		ScanMode:   scanMode,
		Running:    running,
		rows:       make(map[string]*resultRow, 1024),
		order:      make([]string, 0, 1024),
		portCounts: make(map[uint16]uint64, 64),
		subnetMap:  make(map[uint32]*subnetNode, 64),
		follow:     true,
		filterMode: FilterAll,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.searching {
			return m.updateSearch(msg)
		}
		return m.updateNormal(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.rebuildFiltered()

	case ScanEvent:
		m.handleEvent(msg)
		if m.done {
			return m, tea.Quit
		}
		m.rebuildFiltered()
		if m.follow {
			m.cursorToEnd()
		}

	case ScanStats:
		m.stats = msg
		m.tickSparkline()
	}

	return m, nil
}

func (m Model) updateNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Global keys regardless of mode
	switch msg.String() {
	case "ctrl+c", "q":
		m.quitting = true
		return m, tea.Quit
	case "t":
		m.treeMode = !m.treeMode
		m.heatmapMode = false
		m.treeCursor = 0
		m.treeOffset = 0
		return m, nil
	case "h":
		m.heatmapMode = !m.heatmapMode
		m.treeMode = false
		return m, nil
	case "/":
		m.searching = true
		return m, nil
	case "1":
		m.filterMode = FilterAll
		m.rebuildFiltered()
		m.clampCursor()
		return m, nil
	case "2":
		m.filterMode = FilterOpen
		m.rebuildFiltered()
		m.clampCursor()
		return m, nil
	case "3":
		m.filterMode = FilterBanner
		m.rebuildFiltered()
		m.clampCursor()
		return m, nil
	case "f":
		m.follow = !m.follow
		if m.follow {
			m.cursorToEnd()
		}
		return m, nil
	}

	// Tree-mode navigation
	if m.treeMode {
		return m.updateTree(msg)
	}

	// Flat-mode navigation
	vis := m.visibleRows()
	switch msg.String() {
	case "j", "down":
		m.follow = false
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
		}
		m.ensureVisible()
	case "k", "up":
		m.follow = false
		if m.cursor > 0 {
			m.cursor--
		}
		m.ensureVisible()
	case "pgdown", "ctrl+d":
		m.follow = false
		m.cursor += vis
		if m.cursor >= len(m.filtered) {
			m.cursor = len(m.filtered) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.ensureVisible()
	case "pgup", "ctrl+u":
		m.follow = false
		m.cursor -= vis
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.ensureVisible()
	case "g", "home":
		m.follow = false
		m.cursor = 0
		m.offset = 0
	case "G", "end":
		m.follow = true
		m.cursorToEnd()
	case "esc":
		if m.searchText != "" {
			m.searchText = ""
			m.rebuildFiltered()
			m.clampCursor()
		}
	}
	return m, nil
}

// updateTree handles keybindings in tree mode.
func (m Model) updateTree(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	totalLines := m.treeLineCount()
	vis := m.visibleRows()
	switch msg.String() {
	case "j", "down":
		if m.treeCursor < totalLines-1 {
			m.treeCursor++
		}
		m.ensureTreeVisible(vis)
	case "k", "up":
		if m.treeCursor > 0 {
			m.treeCursor--
		}
		m.ensureTreeVisible(vis)
	case "pgdown", "ctrl+d":
		m.treeCursor += vis
		if m.treeCursor >= totalLines {
			m.treeCursor = totalLines - 1
		}
		if m.treeCursor < 0 {
			m.treeCursor = 0
		}
		m.ensureTreeVisible(vis)
	case "pgup", "ctrl+u":
		m.treeCursor -= vis
		if m.treeCursor < 0 {
			m.treeCursor = 0
		}
		m.ensureTreeVisible(vis)
	case "g", "home":
		m.treeCursor = 0
		m.treeOffset = 0
	case "G", "end":
		m.treeCursor = totalLines - 1
		if m.treeCursor < 0 {
			m.treeCursor = 0
		}
		m.ensureTreeVisible(vis)
	case "enter", " ":
		m.toggleTreeNode()
	case "esc":
		if m.searchText != "" {
			m.searchText = ""
			m.rebuildFiltered()
			m.clampCursor()
		}
	}
	return m, nil
}

func (m Model) updateSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.searching = false
	case "enter":
		m.searching = false
	case "backspace":
		if len(m.searchText) > 0 {
			m.searchText = m.searchText[:len(m.searchText)-1]
			m.rebuildFiltered()
			m.clampCursor()
		}
	case "ctrl+u":
		m.searchText = ""
		m.rebuildFiltered()
		m.clampCursor()
	default:
		if len(msg.String()) == 1 {
			m.searchText += msg.String()
			m.rebuildFiltered()
			m.clampCursor()
		}
	}
	return m, nil
}

func (m *Model) handleEvent(ev ScanEvent) {
	switch ev.Type {
	case EvtOpen:
		key := rowKey(ev.IP, ev.Port, ev.Proto)
		if _, exists := m.rows[key]; !exists {
			m.totalAll++
			m.totalOpen++
			m.portCounts[ev.Port]++
			m.topPortsDirty = true
			row := &resultRow{
				IP:    ev.IP,
				Port:  ev.Port,
				Proto: ev.Proto,
				TTL:   ev.TTL,
				State: "open",
				Time:  time.Now(),
				seq:   m.nextSeq,
			}
			m.nextSeq++
			m.rows[key] = row
			m.order = append(m.order, key)
			m.updateTreeData(ev.IP, ev.Port, ev.Proto, ev.TTL, "", "", "open", ev.OSFamily, ev.OSConfidence)
			m.evictOld()
		}

	case EvtBanner:
		key := rowKey(ev.IP, ev.Port, ev.Proto)
		if row, exists := m.rows[key]; exists {
			// Update in place — don't add a second row
			wasBanner := row.State == "banner"
			row.State = "banner"
			row.Banner = ev.Banner
			if ev.Probe != "" {
				row.Service = ev.Probe
			}
			if !wasBanner {
				m.totalBanner++
			}
			m.updateTreeData(ev.IP, ev.Port, ev.Proto, ev.TTL, ev.Probe, ev.Banner, "banner", ev.OSFamily, ev.OSConfidence)
		} else {
			m.totalAll++
			m.totalOpen++
			m.totalBanner++
			m.portCounts[ev.Port]++
			m.topPortsDirty = true
			row := &resultRow{
				IP:      ev.IP,
				Port:    ev.Port,
				Proto:   ev.Proto,
				TTL:     ev.TTL,
				Service: ev.Probe,
				Banner:  ev.Banner,
				State:   "banner",
				Time:    time.Now(),
				seq:     m.nextSeq,
			}
			m.nextSeq++
			m.rows[key] = row
			m.order = append(m.order, key)
			m.updateTreeData(ev.IP, ev.Port, ev.Proto, ev.TTL, ev.Probe, ev.Banner, "banner", ev.OSFamily, ev.OSConfidence)
			m.evictOld()
		}

	case EvtTimeout:
		key := rowKey(ev.IP, ev.Port, ev.Proto)
		if _, exists := m.rows[key]; !exists {
			m.totalAll++
			row := &resultRow{
				IP:    ev.IP,
				Port:  ev.Port,
				Proto: ev.Proto,
				State: "timeout",
				Time:  time.Now(),
				seq:   m.nextSeq,
			}
			m.nextSeq++
			m.rows[key] = row
			m.order = append(m.order, key)
			m.evictOld()
		}

	case EvtDone:
		m.done = true
	}
}

func (m *Model) evictOld() {
	for len(m.order) > maxRows {
		old := m.order[0]
		m.order = m.order[1:]
		delete(m.rows, old)
	}
}

// ── Tree update ──────────────────────────────────────────────────────

// subnetOSSummary returns a compact OS family distribution string for a subnet.
func subnetOSSummary(sn *subnetNode) string {
	counts := make(map[string]int)
	for _, hn := range sn.Hosts {
		if hn.OSFamily != "" {
			counts[hn.OSFamily]++
		}
	}
	if len(counts) == 0 {
		return ""
	}
	// Sort by count descending
	type osCount struct {
		family string
		count  int
	}
	sorted := make([]osCount, 0, len(counts))
	for f, c := range counts {
		sorted = append(sorted, osCount{f, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	var parts []string
	for _, oc := range sorted {
		parts = append(parts, fmt.Sprintf("%s:%d", oc.family, oc.count))
	}
	return "  (" + strings.Join(parts, ", ") + ")"
}

// confRank returns a numeric rank for confidence comparison.
func confRank(conf string) int {
	switch conf {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func parseIPToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIPStr(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", n>>24, (n>>16)&0xFF, (n>>8)&0xFF, n&0xFF)
}

func (m *Model) updateTreeData(ipStr string, port uint16, proto string, ttl uint8, service, bannerStr, state, osFamily, osConf string) {
	ipU32 := parseIPToUint32(ipStr)
	if ipU32 == 0 {
		return
	}
	prefix := ipU32 & 0xFFFFFF00

	sn, ok := m.subnetMap[prefix]
	if !ok {
		sn = &subnetNode{
			Prefix:  prefix,
			Label:   fmt.Sprintf("%s/24", uint32ToIPStr(prefix)),
			HostMap: make(map[uint32]*hostNode, 16),
		}
		m.subnetMap[prefix] = sn
		// Insert sorted by prefix
		idx := sort.Search(len(m.subnets), func(i int) bool {
			return m.subnets[i].Prefix >= prefix
		})
		m.subnets = append(m.subnets, nil)
		copy(m.subnets[idx+1:], m.subnets[idx:])
		m.subnets[idx] = sn
	}

	hn, ok := sn.HostMap[ipU32]
	if !ok {
		hn = &hostNode{IP: ipU32, IPStr: ipStr}
		sn.HostMap[ipU32] = hn
		// Insert sorted by IP
		idx := sort.Search(len(sn.Hosts), func(i int) bool {
			return sn.Hosts[i].IP >= ipU32
		})
		sn.Hosts = append(sn.Hosts, nil)
		copy(sn.Hosts[idx+1:], sn.Hosts[idx:])
		sn.Hosts[idx] = hn
	}

	// Update OS guess if this one is better (higher confidence wins)
	if osFamily != "" && confRank(osConf) > confRank(hn.OSConf) {
		hn.OSFamily = osFamily
		hn.OSConf = osConf
	}

	// Find or create port entry
	found := false
	for _, pe := range hn.Ports {
		if pe.Port == port && pe.Proto == proto {
			pe.State = state
			if bannerStr != "" {
				pe.Banner = bannerStr
			}
			if service != "" {
				pe.Service = service
			}
			pe.TTL = ttl
			found = true
			break
		}
	}
	if !found {
		pe := &portEntry{Port: port, Proto: proto, Service: service, Banner: bannerStr, TTL: ttl, State: state}
		// Insert sorted by port
		idx := sort.Search(len(hn.Ports), func(i int) bool {
			return hn.Ports[i].Port >= port
		})
		hn.Ports = append(hn.Ports, nil)
		copy(hn.Ports[idx+1:], hn.Ports[idx:])
		hn.Ports[idx] = pe
		sn.Count++
	}
}

// ── Top ports ────────────────────────────────────────────────────────

func (m *Model) rebuildTopPorts() {
	if !m.topPortsDirty {
		return
	}
	m.topPortsDirty = false

	// Collect all
	pcs := make([]portCount, 0, len(m.portCounts))
	for p, c := range m.portCounts {
		pcs = append(pcs, portCount{p, c})
	}
	sort.Slice(pcs, func(i, j int) bool {
		return pcs[i].Count > pcs[j].Count
	})
	if len(pcs) > 10 {
		pcs = pcs[:10]
	}
	m.topPorts = pcs
}

// ── Sparkline ────────────────────────────────────────────────────────

func (m *Model) tickSparkline() {
	cur := m.totalOpen
	delta := cur - m.sparkPrev
	m.sparkPrev = cur
	m.sparkBuf[m.sparkIdx] = delta
	m.sparkIdx = (m.sparkIdx + 1) % 60
	if m.sparkFilled < 60 {
		m.sparkFilled++
	}
}

func (m Model) renderSparkline() string {
	if m.sparkFilled == 0 {
		return ""
	}
	sparks := []rune("▁▂▃▄▅▆▇█")
	// Find max value
	var maxVal uint64
	for i := 0; i < m.sparkFilled; i++ {
		idx := (m.sparkIdx - m.sparkFilled + i + 60) % 60
		if m.sparkBuf[idx] > maxVal {
			maxVal = m.sparkBuf[idx]
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	var sb strings.Builder
	for i := 0; i < m.sparkFilled; i++ {
		idx := (m.sparkIdx - m.sparkFilled + i + 60) % 60
		level := int(m.sparkBuf[idx] * 7 / maxVal)
		if level > 7 {
			level = 7
		}
		sb.WriteRune(sparks[level])
	}
	return sb.String()
}

func (m *Model) rebuildFiltered() {
	m.filtered = m.filtered[:0]
	needle := strings.ToLower(m.searchText)

	for _, key := range m.order {
		row, ok := m.rows[key]
		if !ok {
			continue
		}
		// Preset filter
		switch m.filterMode {
		case FilterOpen:
			if row.State != "open" && row.State != "banner" {
				continue
			}
		case FilterBanner:
			if row.State != "banner" {
				continue
			}
		}
		// Text filter
		if needle != "" {
			hay := strings.ToLower(row.IP + " " + fmt.Sprintf("%d", row.Port) + " " + row.Proto + " " + row.Service + " " + row.Banner)
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		m.filtered = append(m.filtered, row)
	}
}

func (m *Model) clampCursor() {
	if len(m.filtered) == 0 {
		m.cursor = 0
		m.offset = 0
		return
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}
	m.ensureVisible()
}

func (m *Model) cursorToEnd() {
	if len(m.filtered) > 0 {
		m.cursor = len(m.filtered) - 1
	} else {
		m.cursor = 0
	}
	m.ensureVisible()
}

func (m *Model) ensureVisible() {
	vis := m.visibleRows()
	if vis <= 0 {
		vis = 1
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+vis {
		m.offset = m.cursor - vis + 1
	}
}

// visibleRows returns how many table rows fit on screen.
// Layout: 3 header lines + 1 col header + 1 separator + table + 1 separator + detailHeight + 1 help
func (m Model) visibleRows() int {
	detail := m.detailHeight()
	chrome := 3 + 1 + 1 + 1 + detail + 1
	rows := m.height - chrome
	if rows < 1 {
		rows = 1
	}
	return rows
}

func (m Model) detailHeight() int {
	h := m.height / 4
	if h < 3 {
		h = 3
	}
	if h > 10 {
		h = 10
	}
	return h
}

// ── View ──────────────────────────────────────────────────────────────

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if m.done {
		return ""
	}

	w := m.width
	if w < 40 {
		w = 80
	}

	var b strings.Builder

	// Line 1: header
	m.renderHeader(&b, w)
	// Line 2: progress + stats (with sparkline)
	m.renderProgress(&b, w)
	// Port histogram (compact, 1 line)
	m.renderPortHistogram(&b, w)
	// Line 3: filter tabs + search
	m.renderFilterBar(&b, w)

	if m.heatmapMode {
		m.renderHeatmap(&b, w)
		m.renderHelp(&b, w)
	} else if m.treeMode {
		m.renderTreeView(&b, w)
		m.renderHelp(&b, w)
	} else {
		// Column header
		m.renderColHeader(&b, w)
		// Table rows
		m.renderTable(&b, w)
		// Detail pane
		m.renderDetail(&b, w)
		// Help line
		m.renderHelp(&b, w)
	}

	return b.String()
}

func (m Model) renderHeader(b *strings.Builder, w int) {
	title := styleAccent.Render("rs_scan")
	meta := styleDim.Render(fmt.Sprintf(" %s · %s · %s", m.ScanMode, truncStr(m.Target, 30), truncStr(m.PortSpec, 30)))
	b.WriteString(" " + title + meta + "\n")
}

func (m Model) renderProgress(b *strings.Builder, w int) {
	// Progress bar (compact)
	barW := 20
	if w > 120 {
		barW = 30
	}
	filled := int(m.stats.Progress * float64(barW))
	if filled > barW {
		filled = barW
	}
	empty := barW - filled
	bar := styleBar.Render(strings.Repeat("█", filled)) + styleBarTrail.Render(strings.Repeat("░", empty))

	pct := fmt.Sprintf("%3.0f%%", m.stats.Progress*100)

	eta := ""
	if m.stats.Progress > 0.001 && m.stats.Progress < 1 && m.stats.Rate > 0 {
		rem := m.stats.Elapsed.Seconds() * (1 - m.stats.Progress) / m.stats.Progress
		if rem < 60 {
			eta = fmt.Sprintf(" ETA %0.0fs", rem)
		} else {
			eta = fmt.Sprintf(" ETA %dm%02ds", int(rem)/60, int(rem)%60)
		}
	}
	if m.stats.Progress >= 1 {
		eta = " done"
	}

	spark := m.renderSparkline()
	sparkStr := ""
	if spark != "" {
		sparkStr = " " + styleBar.Render(spark)
	}

	stats := fmt.Sprintf("  %s/s  Sent %s  Open%s %s  Ban %s  Drop %s",
		fmtCompact(uint64(m.stats.Rate)),
		fmtCompact(m.stats.Sent),
		sparkStr,
		fmtCompact(m.stats.Open),
		fmtCompact(m.stats.Banners),
		fmtCompact(m.stats.Drops))

	elapsed := m.stats.Elapsed.Truncate(time.Second).String()

	line := fmt.Sprintf(" %s %s%s%s  %s", bar, pct, eta, styleDim.Render(stats), styleDim.Render(elapsed))
	b.WriteString(line + "\n")
}

func (m Model) renderFilterBar(b *strings.Builder, w int) {
	tabAll := m.renderTab("1:All", int(m.totalAll), FilterAll)
	tabOpen := m.renderTab("2:Open", int(m.totalOpen), FilterOpen)
	tabBanner := m.renderTab("3:Banner", int(m.totalBanner), FilterBanner)

	tabs := " " + tabAll + " " + tabOpen + " " + tabBanner

	// Search indicator
	search := ""
	if m.searching {
		search = styleFilterBox.Render("  /" + m.searchText + "▌")
	} else if m.searchText != "" {
		search = styleDim.Render("  /") + styleFilterBox.Render(m.searchText)
	}

	// Follow indicator
	followInd := ""
	if m.follow {
		followInd = styleDim.Render("  [follow]")
	}

	b.WriteString(tabs + search + followInd + "\n")
}

func (m Model) renderTab(label string, count int, mode int) string {
	text := fmt.Sprintf(" %s:%d ", label, count)
	if m.filterMode == mode {
		return styleTabActive.Render(text)
	}
	return styleTabInactive.Render(text)
}

// Column widths — fixed layout for predictable alignment
const (
	colIP      = 18
	colPort    = 6
	colProto   = 5
	colService = 12
	// Banner takes the rest
)

func (m Model) renderColHeader(b *strings.Builder, w int) {
	banW := w - colIP - colPort - colProto - colService - 4 // 4 for padding
	if banW < 10 {
		banW = 10
	}
	line := fmt.Sprintf(" %-*s %-*s %-*s %-*s %s",
		colIP, "IP",
		colPort, "PORT",
		colProto, "PROTO",
		colService, "SERVICE",
		"BANNER")
	b.WriteString(styleColHeader.Render(line))
	b.WriteString("\n")

	sep := styleSep.Render(" " + strings.Repeat("─", w-2))
	b.WriteString(sep + "\n")
}

func (m Model) renderTable(b *strings.Builder, w int) {
	vis := m.visibleRows()
	banW := w - colIP - colPort - colProto - colService - 5
	if banW < 10 {
		banW = 10
	}

	end := m.offset + vis
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	for i := m.offset; i < end; i++ {
		row := m.filtered[i]
		isCursor := (i == m.cursor)

		ip := padRight(row.IP, colIP)
		port := padRight(fmt.Sprintf("%d", row.Port), colPort)
		proto := padRight(row.Proto, colProto)
		svc := padRight(row.Service, colService)
		ban := cleanBannerOneLine(row.Banner, banW)

		if isCursor {
			// Highlighted row — render with cursor background
			marker := styleAccent.Render("▸")
			content := fmt.Sprintf("%s %s %s %s %s", ip, port, proto, svc, ban)
			b.WriteString(marker + styleCursor.Render(truncStr(content, w-2)) + "\n")
		} else {
			b.WriteString(m.renderRow(row, ip, port, proto, svc, ban, w))
		}
	}

	// Fill empty space
	for i := end - m.offset; i < vis; i++ {
		b.WriteString(styleDim.Render(" ~") + "\n")
	}
}

func (m Model) renderRow(row *resultRow, ip, port, proto, svc, ban string, w int) string {
	var stateStyle, svcStyle, banStyle func(string) string

	switch row.State {
	case "open":
		stateStyle = func(s string) string { return styleOpen.Render(s) }
		svcStyle = func(s string) string { return styleDim.Render(s) }
		banStyle = func(s string) string { return styleDim.Render(s) }
	case "banner":
		stateStyle = func(s string) string { return styleBanner.Render(s) }
		svcStyle = func(s string) string { return styleService.Render(s) }
		banStyle = func(s string) string { return styleBanTxt.Render(s) }
	case "timeout":
		stateStyle = func(s string) string { return styleTimeout.Render(s) }
		svcStyle = func(s string) string { return styleTimeout.Render(s) }
		banStyle = func(s string) string { return styleTimeout.Render(s) }
	default:
		stateStyle = func(s string) string { return s }
		svcStyle = stateStyle
		banStyle = stateStyle
	}

	return fmt.Sprintf(" %s %s %s %s %s\n",
		stateStyle(ip),
		stateStyle(port),
		stateStyle(proto),
		svcStyle(svc),
		banStyle(ban))
}

func (m Model) renderDetail(b *strings.Builder, w int) {
	detailH := m.detailHeight()

	// Separator
	b.WriteString(styleSep.Render(" " + strings.Repeat("─", w-2)) + "\n")

	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		for i := 0; i < detailH-1; i++ {
			b.WriteString("\n")
		}
		return
	}

	row := m.filtered[m.cursor]

	// Detail header
	header := fmt.Sprintf(" %s:%d/%s", row.IP, row.Port, row.Proto)
	if row.Service != "" {
		header += fmt.Sprintf("  [%s]", row.Service)
	}
	header += fmt.Sprintf("  ttl=%d  %s", row.TTL, row.State)
	b.WriteString(styleDim.Render(header) + "\n")

	// Banner content
	lines := splitBannerLines(row.Banner, w-2)
	shown := 0
	for _, line := range lines {
		if shown >= detailH-2 {
			break
		}
		b.WriteString(" " + styleDetailText.Render(line) + "\n")
		shown++
	}
	// Fill remaining
	for i := shown; i < detailH-2; i++ {
		b.WriteString("\n")
	}
}

func (m Model) renderHelp(b *strings.Builder, w int) {
	var help string
	if m.treeMode {
		help = " q:quit  ↑↓/jk:scroll  enter:expand  t:flat  h:heatmap  1-3:filter  /:search"
	} else if m.heatmapMode {
		help = " q:quit  h:close  t:tree  1-3:filter  /:search  f:follow"
	} else {
		help = " q:quit  ↑↓/jk:scroll  g/G:top/end  1-3:filter  /:search  f:follow  t:tree  h:heatmap"
	}
	b.WriteString(styleHelp.Render(truncStr(help, w)))
}

// ── Port Histogram ───────────────────────────────────────────────────

func (m *Model) renderPortHistogram(b *strings.Builder, w int) {
	m.rebuildTopPorts()
	if len(m.topPorts) == 0 {
		return
	}

	// Compact single-line histogram: top ports with mini bars
	maxCount := m.topPorts[0].Count
	if maxCount == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString(" ")
	for i, pc := range m.topPorts {
		if i > 0 {
			sb.WriteString("  ")
		}
		// Bar width proportional to count, max 12 chars
		barLen := int(pc.Count * 12 / maxCount)
		if barLen < 1 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		entry := fmt.Sprintf("%d %s %s", pc.Port, styleBar.Render(bar), fmtCompact(pc.Count))
		sb.WriteString(entry)
		// Truncate if too wide
		if sb.Len() > w-4 {
			break
		}
	}
	b.WriteString(styleDim.Render(" Top:") + sb.String() + "\n")
}

// ── Tree View ────────────────────────────────────────────────────────

// treeLineCount returns the total number of visible lines in the tree.
func (m Model) treeLineCount() int {
	count := 0
	for _, sn := range m.subnets {
		count++ // subnet line
		if sn.Expanded {
			for _, hn := range sn.Hosts {
				count++ // host line
				if hn.Expanded {
					count += len(hn.Ports) // port lines
				}
			}
		}
	}
	return count
}

// treeLineType identifies what a flattened tree line points to.
type treeLineType int

const (
	treeLineSubnet treeLineType = iota
	treeLineHost
	treeLinePort
)

type treeLine struct {
	Type   treeLineType
	Subnet *subnetNode
	Host   *hostNode
	Port   *portEntry
}

// flattenTree returns the visible tree lines.
func (m Model) flattenTree() []treeLine {
	var lines []treeLine
	for _, sn := range m.subnets {
		lines = append(lines, treeLine{Type: treeLineSubnet, Subnet: sn})
		if sn.Expanded {
			for _, hn := range sn.Hosts {
				lines = append(lines, treeLine{Type: treeLineHost, Subnet: sn, Host: hn})
				if hn.Expanded {
					for _, pe := range hn.Ports {
						lines = append(lines, treeLine{Type: treeLinePort, Subnet: sn, Host: hn, Port: pe})
					}
				}
			}
		}
	}
	return lines
}

func (m *Model) toggleTreeNode() {
	lines := m.flattenTree()
	if m.treeCursor < 0 || m.treeCursor >= len(lines) {
		return
	}
	line := lines[m.treeCursor]
	switch line.Type {
	case treeLineSubnet:
		line.Subnet.Expanded = !line.Subnet.Expanded
	case treeLineHost:
		line.Host.Expanded = !line.Host.Expanded
	}
}

func (m *Model) ensureTreeVisible(vis int) {
	if vis <= 0 {
		vis = 1
	}
	if m.treeCursor < m.treeOffset {
		m.treeOffset = m.treeCursor
	}
	if m.treeCursor >= m.treeOffset+vis {
		m.treeOffset = m.treeCursor - vis + 1
	}
}

func (m Model) renderTreeView(b *strings.Builder, w int) {
	vis := m.visibleRows()
	lines := m.flattenTree()

	end := m.treeOffset + vis
	if end > len(lines) {
		end = len(lines)
	}

	for i := m.treeOffset; i < end; i++ {
		line := lines[i]
		isCursor := (i == m.treeCursor)
		var text string

		switch line.Type {
		case treeLineSubnet:
			sn := line.Subnet
			arrow := "▶"
			if sn.Expanded {
				arrow = "▼"
			}
			hostCount := len(sn.Hosts)
			osSummary := subnetOSSummary(sn)
			text = fmt.Sprintf(" %s %s          %d hosts  %d open%s",
				arrow, padRight(sn.Label, 22), hostCount, sn.Count, osSummary)
			if isCursor {
				b.WriteString(styleAccent.Render("▸") + styleCursor.Render(truncStr(text, w-2)) + "\n")
			} else {
				b.WriteString(styleOpen.Render(truncStr(text, w)) + "\n")
			}

		case treeLineHost:
			hn := line.Host
			arrow := "▶"
			if hn.Expanded {
				arrow = "▼"
			}
			osTag := ""
			if hn.OSFamily != "" {
				osTag = fmt.Sprintf("  [%s %s]", hn.OSFamily, hn.OSConf)
			}
			text = fmt.Sprintf("   %s %s            %d ports%s", arrow, padRight(hn.IPStr, 18), len(hn.Ports), osTag)
			if isCursor {
				b.WriteString(styleAccent.Render("▸") + styleCursor.Render(truncStr(text, w-2)) + "\n")
			} else {
				// Color based on whether any port has banner
				hasBanner := false
				for _, pe := range hn.Ports {
					if pe.State == "banner" {
						hasBanner = true
						break
					}
				}
				if hasBanner {
					b.WriteString(styleBanner.Render(truncStr(text, w)) + "\n")
				} else {
					b.WriteString(truncStr(text, w) + "\n")
				}
			}

		case treeLinePort:
			pe := line.Port
			svc := padRight(pe.Service, 10)
			ban := cleanBannerOneLine(pe.Banner, w-50)
			text = fmt.Sprintf("       %s/%-4s %-6s %s %s", padRight(fmt.Sprintf("%d", pe.Port), 5), pe.Proto, pe.State, svc, ban)
			if isCursor {
				b.WriteString(styleAccent.Render("▸") + styleCursor.Render(truncStr(text, w-2)) + "\n")
			} else {
				switch pe.State {
				case "banner":
					b.WriteString(fmt.Sprintf("       %s/%-4s %s %s %s\n",
						styleBanner.Render(padRight(fmt.Sprintf("%d", pe.Port), 5)),
						styleBanner.Render(pe.Proto),
						styleBanner.Render(padRight(pe.State, 6)),
						styleService.Render(svc),
						styleBanTxt.Render(ban)))
				default:
					b.WriteString(fmt.Sprintf("       %s/%-4s %s %s %s\n",
						styleOpen.Render(padRight(fmt.Sprintf("%d", pe.Port), 5)),
						styleOpen.Render(pe.Proto),
						styleOpen.Render(padRight(pe.State, 6)),
						styleDim.Render(svc),
						styleDim.Render(ban)))
				}
			}
		}
	}

	// Fill empty space
	for i := end - m.treeOffset; i < vis; i++ {
		b.WriteString(styleDim.Render(" ~") + "\n")
	}

	// Separator
	b.WriteString(styleSep.Render(" " + strings.Repeat("─", w-2)) + "\n")
}

// ── Heatmap View ─────────────────────────────────────────────────────

func (m Model) renderHeatmap(b *strings.Builder, w int) {
	vis := m.height - 8 // leave room for header, progress, histogram, filter, help
	if vis < 4 {
		vis = 4
	}

	if len(m.subnets) == 0 {
		b.WriteString(styleDim.Render(" (no data for heatmap)") + "\n")
		for i := 1; i < vis; i++ {
			b.WriteString("\n")
		}
		return
	}

	// Determine grid dimensions: 16 columns, up to vis rows
	cols := 16
	if cols*3+8 > w { // 3 chars per cell + row label
		cols = (w - 8) / 3
		if cols < 4 {
			cols = 4
		}
	}
	rows := vis - 3 // header + column labels + padding
	if rows > 16 {
		rows = 16
	}
	if rows < 1 {
		rows = 1
	}

	// Build a list of all /24 prefixes with counts
	type heatCell struct {
		prefix uint32
		count  int
	}
	var cells []heatCell
	for _, sn := range m.subnets {
		cells = append(cells, heatCell{sn.Prefix, sn.Count})
	}

	totalCells := rows * cols
	if len(cells) > totalCells {
		cells = cells[:totalCells]
	}

	// Header
	b.WriteString(styleAccent.Render(" Subnet Heatmap") + styleDim.Render(fmt.Sprintf("  (%d subnets)", len(m.subnets))) + "\n")

	// Column labels
	colHeader := "        "
	for c := 0; c < cols && c < len(cells); c++ {
		colHeader += fmt.Sprintf("%-3d", c)
	}
	b.WriteString(styleDim.Render(truncStr(colHeader, w)) + "\n")

	// Grid
	idx := 0
	for r := 0; r < rows; r++ {
		rowStr := fmt.Sprintf(" %3d  ", r)
		hasContent := false
		for c := 0; c < cols; c++ {
			if idx < len(cells) {
				cell := cells[idx]
				idx++
				if cell.count > 10 {
					rowStr += styleHeatHigh.Render("██ ")
					hasContent = true
				} else if cell.count >= 3 {
					rowStr += styleHeatMed.Render("██ ")
					hasContent = true
				} else if cell.count >= 1 {
					rowStr += styleHeatLow.Render("░░ ")
					hasContent = true
				} else {
					rowStr += styleHeatNone.Render("·· ")
				}
			} else {
				rowStr += "   "
			}
		}
		if hasContent || r == 0 {
			b.WriteString(truncStr(rowStr, w) + "\n")
		} else {
			b.WriteString("\n")
		}
	}

	// Fill remaining
	linesUsed := 2 + rows // header + col header + grid rows
	for i := linesUsed; i < vis; i++ {
		b.WriteString("\n")
	}

	// Separator
	b.WriteString(styleSep.Render(" " + strings.Repeat("─", w-2)) + "\n")
}

// ── Banner helpers ────────────────────────────────────────────────────

// isASCIIPrint returns true for bytes 0x20-0x7E (space through tilde).
// Rejects all non-ASCII, control chars, DEL, and Unicode — anything that
// could render weird in a terminal or contain ANSI escape sequences.
func isASCIIPrint(b byte) bool {
	return b >= 0x20 && b <= 0x7E
}

// sanitize replaces every non-ASCII-printable byte with \xHH.
// Tabs become spaces. Operates on raw bytes, not runes, so no
// multi-byte Unicode sneaks through.
func sanitize(raw string) string {
	var sb strings.Builder
	sb.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b == '\t' {
			sb.WriteByte(' ')
		} else if isASCIIPrint(b) {
			sb.WriteByte(b)
		} else {
			fmt.Fprintf(&sb, "\\x%02x", b)
		}
	}
	return sb.String()
}

// cleanBannerOneLine extracts a single-line, hex-escaped summary from raw banner.
func cleanBannerOneLine(raw string, maxW int) string {
	if raw == "" {
		return ""
	}

	// Take up to first newline
	line := raw
	for i := 0; i < len(line); i++ {
		if line[i] == '\r' || line[i] == '\n' {
			line = line[:i]
			break
		}
	}

	line = sanitize(line)
	line = strings.TrimSpace(line)

	if len(line) > maxW {
		if maxW > 1 {
			line = line[:maxW-1] + "…"
		} else {
			line = line[:maxW]
		}
	}
	return line
}

// splitBannerLines splits raw banner into display lines, sanitizing each.
func splitBannerLines(raw string, maxW int) []string {
	if raw == "" {
		return []string{styleDim.Render("(no banner data)")}
	}

	// Normalize line endings then split
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	parts := strings.Split(s, "\n")

	var out []string
	for _, p := range parts {
		line := sanitize(p)
		if len(line) > maxW {
			line = line[:maxW]
		}
		out = append(out, line)
	}
	return out
}

// ── Formatting helpers ────────────────────────────────────────────────

func fmtNum(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1_000_000 {
		return fmt.Sprintf("%d,%03d", n/1000, n%1000)
	}
	return fmt.Sprintf("%d,%03d,%03d", n/1_000_000, (n/1000)%1000, n%1000)
}

func fmtCompact(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 10_000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	if n < 1_000_000 {
		return fmt.Sprintf("%.0fk", float64(n)/1000)
	}
	if n < 10_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	return fmt.Sprintf("%.0fM", float64(n)/1_000_000)
}

func padRight(s string, w int) string {
	if len(s) >= w {
		return s[:w]
	}
	return s + strings.Repeat(" ", w-len(s))
}

func truncStr(s string, w int) string {
	if len(s) <= w {
		return s
	}
	if w < 2 {
		return s[:w]
	}
	return s[:w-1] + "…"
}

// ── TextPrinter (non-TUI mode) ───────────────────────────────────────

type TextPrinter struct {
	Verbose bool
}

func (p *TextPrinter) PrintEvent(ev ScanEvent) {
	switch ev.Type {
	case EvtOpen:
		fmt.Printf("\n[+] OPEN: %s:%d (%s)\n", ev.IP, ev.Port, ev.Proto)
	case EvtBanner:
		ban := cleanBannerOneLine(ev.Banner, 120)
		if ev.Probe != "" {
			fmt.Printf("\n[*] BANNER: %s:%d (%s) [%s] %s\n", ev.IP, ev.Port, ev.Proto, ev.Probe, ban)
		} else {
			fmt.Printf("\n[*] BANNER: %s:%d (%s) %s\n", ev.IP, ev.Port, ev.Proto, ban)
		}
	case EvtTimeout:
		if p.Verbose {
			fmt.Printf("\n[-] TIMEOUT: %s:%d (%s)\n", ev.IP, ev.Port, ev.Proto)
		}
	case EvtInfo:
		fmt.Printf("%s\n", ev.Msg)
	}
}

func (p *TextPrinter) PrintStats(s ScanStats) {
	fmt.Printf("\rPPS: %.0f | Sent: %d | Recv: %d | Open: %d | Drops: %d",
		s.Rate, s.Sent, s.Recv, s.Open, s.Drops)
}
