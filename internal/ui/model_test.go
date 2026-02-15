package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestModelUpdate_OpenEvent(t *testing.T) {
	var running int32 = 1
	m := NewModel("192.168.1.0/24", "22,80", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40

	ev := ScanEvent{
		Type:  EvtOpen,
		IP:    "192.168.1.1",
		Port:  22,
		Proto: "tcp",
		TTL:   64,
	}

	newModel, _ := m.Update(ev)
	model := newModel.(Model)

	if len(model.rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(model.rows))
	}
	row := model.rows["192.168.1.1:22/tcp"]
	if row == nil {
		t.Fatal("expected row for 192.168.1.1:22/tcp")
	}
	if row.State != "open" {
		t.Fatalf("expected state=open, got %s", row.State)
	}
	if row.IP != "192.168.1.1" {
		t.Fatalf("expected IP=192.168.1.1, got %s", row.IP)
	}
}

func TestModelUpdate_BannerUpdatesExistingOpen(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.1", "22", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40

	// First: OPEN event
	newModel, _ := m.Update(ScanEvent{
		Type: EvtOpen, IP: "10.0.0.1", Port: 22, Proto: "tcp", TTL: 64,
	})
	m = newModel.(Model)

	if len(m.rows) != 1 {
		t.Fatalf("expected 1 row after OPEN, got %d", len(m.rows))
	}

	// Second: BANNER event for same host:port — should update in place
	newModel, _ = m.Update(ScanEvent{
		Type: EvtBanner, IP: "10.0.0.1", Port: 22, Proto: "tcp",
		Banner: "SSH-2.0-OpenSSH_8.9p1", Probe: "ssh",
	})
	m = newModel.(Model)

	// Still 1 row, not 2
	if len(m.rows) != 1 {
		t.Fatalf("expected 1 row after BANNER (dedup), got %d", len(m.rows))
	}
	row := m.rows["10.0.0.1:22/tcp"]
	if row.State != "banner" {
		t.Fatalf("expected state=banner, got %s", row.State)
	}
	if row.Banner != "SSH-2.0-OpenSSH_8.9p1" {
		t.Fatalf("banner not updated: %s", row.Banner)
	}
	if row.Service != "ssh" {
		t.Fatalf("service not updated: %s", row.Service)
	}
}

func TestModelUpdate_StatsEvent(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/8", "80", "eth0", "TCP SYN", &running)

	stats := ScanStats{
		Sent:     1000,
		Recv:     50,
		Open:     10,
		Progress: 0.5,
		Rate:     5000,
	}

	newModel, _ := m.Update(stats)
	model := newModel.(Model)

	if model.stats.Sent != 1000 {
		t.Fatalf("expected sent=1000, got %d", model.stats.Sent)
	}
	if model.stats.Progress != 0.5 {
		t.Fatalf("expected progress=0.5, got %f", model.stats.Progress)
	}
}

func TestModelUpdate_DoneEvent(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.1", "80", "eth0", "TCP SYN", &running)

	ev := ScanEvent{Type: EvtDone}

	_, cmd := m.Update(ev)

	// EvtDone should produce a tea.Quit command
	if cmd == nil {
		t.Fatal("expected quit command on EvtDone")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Fatalf("expected tea.QuitMsg, got %T", msg)
	}
}

func TestModelUpdate_WindowSize(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.1", "80", "eth0", "TCP SYN", &running)

	newModel, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	model := newModel.(Model)

	if model.width != 120 {
		t.Fatalf("expected width=120, got %d", model.width)
	}
	if model.height != 40 {
		t.Fatalf("expected height=40, got %d", model.height)
	}
}

func TestModelView_Renders(t *testing.T) {
	var running int32 = 1
	m := NewModel("192.168.1.0/24", "22,80", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40

	// Add a result so there's something to render
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "192.168.1.1", Port: 22, Proto: "tcp", TTL: 64})
	m.rebuildFiltered()

	v := m.View()
	if !strings.Contains(v, "rs_scan") {
		t.Fatal("view should contain rs_scan header")
	}
	if !strings.Contains(v, "IP") {
		t.Fatal("view should contain column headers")
	}
	if !strings.Contains(v, "192.168.1.1") {
		t.Fatal("view should contain result IP")
	}
}

func TestModelFilterBanner(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "22,80", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40

	// Add mixed results
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.1", Port: 22, Proto: "tcp"})
	m.handleEvent(ScanEvent{Type: EvtBanner, IP: "10.0.0.2", Port: 80, Proto: "tcp", Banner: "HTTP/1.1 200 OK"})
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.3", Port: 22, Proto: "tcp"})

	// Filter: All
	m.filterMode = FilterAll
	m.rebuildFiltered()
	if len(m.filtered) != 3 {
		t.Fatalf("FilterAll: expected 3, got %d", len(m.filtered))
	}

	// Filter: Banner only
	m.filterMode = FilterBanner
	m.rebuildFiltered()
	if len(m.filtered) != 1 {
		t.Fatalf("FilterBanner: expected 1, got %d", len(m.filtered))
	}
	if m.filtered[0].IP != "10.0.0.2" {
		t.Fatalf("FilterBanner: expected 10.0.0.2, got %s", m.filtered[0].IP)
	}

	// Filter: Open (includes both open and banner)
	m.filterMode = FilterOpen
	m.rebuildFiltered()
	if len(m.filtered) != 3 {
		t.Fatalf("FilterOpen: expected 3, got %d", len(m.filtered))
	}
}

func TestModelSearchFilter(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "22,80,443", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40

	m.handleEvent(ScanEvent{Type: EvtBanner, IP: "10.0.0.1", Port: 80, Proto: "tcp", Banner: "HTTP/1.1 200 OK", Probe: "http"})
	m.handleEvent(ScanEvent{Type: EvtBanner, IP: "10.0.0.2", Port: 22, Proto: "tcp", Banner: "SSH-2.0-OpenSSH_8.9", Probe: "ssh"})
	m.handleEvent(ScanEvent{Type: EvtBanner, IP: "10.0.0.3", Port: 443, Proto: "tcp", Banner: "TLS data", Probe: "tls"})

	// Search for "ssh"
	m.searchText = "ssh"
	m.rebuildFiltered()
	if len(m.filtered) != 1 {
		t.Fatalf("search 'ssh': expected 1, got %d", len(m.filtered))
	}
	if m.filtered[0].Port != 22 {
		t.Fatalf("search 'ssh': expected port 22, got %d", m.filtered[0].Port)
	}

	// Search for "10.0.0.1" (IP match)
	m.searchText = "10.0.0.1"
	m.rebuildFiltered()
	if len(m.filtered) != 1 {
		t.Fatalf("search '10.0.0.1': expected 1, got %d", len(m.filtered))
	}
}

func TestModelScrolling(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/16", "80", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 20 // small terminal

	// Add many results via Update (which triggers follow)
	for i := 0; i < 50; i++ {
		newModel, _ := m.Update(ScanEvent{
			Type:  EvtOpen,
			IP:    "10.0.0.1",
			Port:  uint16(1000 + i),
			Proto: "tcp",
		})
		m = newModel.(Model)
	}

	// Should be at end (follow mode)
	if m.cursor != 49 {
		t.Fatalf("expected cursor at 49 (follow), got %d", m.cursor)
	}

	// Scroll up
	m.follow = false
	m.cursor = 0
	m.ensureVisible()
	if m.offset != 0 {
		t.Fatalf("expected offset=0, got %d", m.offset)
	}
}

func TestModelEviction(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/8", "80", "eth0", "TCP SYN", &running)

	// Add more than maxRows
	for i := 0; i < maxRows+100; i++ {
		m.handleEvent(ScanEvent{
			Type:  EvtOpen,
			IP:    "10.0.0.1",
			Port:  uint16(i % 65535),
			Proto: "tcp",
		})
	}

	if len(m.order) > maxRows {
		t.Fatalf("expected <= %d rows, got %d", maxRows, len(m.order))
	}
}

func TestCleanBannerOneLine(t *testing.T) {
	tests := []struct {
		raw  string
		maxW int
		want string
	}{
		{"", 80, ""},
		{"SSH-2.0-OpenSSH_8.9p1", 80, "SSH-2.0-OpenSSH_8.9p1"},
		{"HTTP/1.1 200 OK\r\nServer: nginx", 80, "HTTP/1.1 200 OK"},
		{"binary\x00data\x01here", 80, `binary\x00data\x01here`},
		{"long " + strings.Repeat("x", 100), 20, "long " + strings.Repeat("x", 14) + "…"},
	}
	for _, tt := range tests {
		got := cleanBannerOneLine(tt.raw, tt.maxW)
		if got != tt.want {
			t.Errorf("cleanBannerOneLine(%q, %d) = %q, want %q", tt.raw, tt.maxW, got, tt.want)
		}
	}
}

func TestFmtNum(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{1234567, "1,234,567"},
	}
	for _, tt := range tests {
		got := fmtNum(tt.n)
		if got != tt.want {
			t.Errorf("fmtNum(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestFmtCompact(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1500, "1.5k"},
		{49823, "50k"},
		{1234567, "1.2M"},
		{12345678, "12M"},
	}
	for _, tt := range tests {
		got := fmtCompact(tt.n)
		if got != tt.want {
			t.Errorf("fmtCompact(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// ── Cumulative counter tests ─────────────────────────────────────────

func TestCumulativeCounters_Basic(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "22,80", "eth0", "TCP SYN", &running)

	// EvtOpen: totalAll++, totalOpen++
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.1", Port: 22, Proto: "tcp"})
	if m.totalAll != 1 || m.totalOpen != 1 || m.totalBanner != 0 {
		t.Fatalf("after EvtOpen: all=%d open=%d banner=%d", m.totalAll, m.totalOpen, m.totalBanner)
	}

	// EvtBanner updating existing open: totalBanner++ only
	m.handleEvent(ScanEvent{Type: EvtBanner, IP: "10.0.0.1", Port: 22, Proto: "tcp", Banner: "SSH-2.0"})
	if m.totalAll != 1 || m.totalOpen != 1 || m.totalBanner != 1 {
		t.Fatalf("after EvtBanner(update): all=%d open=%d banner=%d", m.totalAll, m.totalOpen, m.totalBanner)
	}

	// EvtBanner for new key: totalAll++, totalOpen++, totalBanner++
	m.handleEvent(ScanEvent{Type: EvtBanner, IP: "10.0.0.2", Port: 80, Proto: "tcp", Banner: "HTTP/1.1"})
	if m.totalAll != 2 || m.totalOpen != 2 || m.totalBanner != 2 {
		t.Fatalf("after EvtBanner(new): all=%d open=%d banner=%d", m.totalAll, m.totalOpen, m.totalBanner)
	}

	// EvtTimeout for new key: totalAll++ only
	m.handleEvent(ScanEvent{Type: EvtTimeout, IP: "10.0.0.3", Port: 22, Proto: "tcp"})
	if m.totalAll != 3 || m.totalOpen != 2 || m.totalBanner != 2 {
		t.Fatalf("after EvtTimeout: all=%d open=%d banner=%d", m.totalAll, m.totalOpen, m.totalBanner)
	}
}

func TestCumulativeCounters_SurviveEviction(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/8", "80", "eth0", "TCP SYN", &running)

	total := maxRows + 500
	for i := 0; i < total; i++ {
		m.handleEvent(ScanEvent{
			Type:  EvtOpen,
			IP:    "10.0.0.1",
			Port:  uint16(i % 65535),
			Proto: "tcp",
		})
	}

	// order is capped but totalAll reflects all events
	if len(m.order) > maxRows {
		t.Fatalf("order should be <= %d, got %d", maxRows, len(m.order))
	}
	if m.totalAll != uint64(total) {
		t.Fatalf("totalAll should be %d, got %d", total, m.totalAll)
	}
	if m.totalOpen != uint64(total) {
		t.Fatalf("totalOpen should be %d, got %d", total, m.totalOpen)
	}
}

// ── Tree view tests ──────────────────────────────────────────────────

func TestTreeView_StructureAndCounts(t *testing.T) {
	var running int32 = 1
	m := NewModel("192.168.1.0/24", "22,80,443", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40

	// Add results from two subnets
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "192.168.1.1", Port: 22, Proto: "tcp"})
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "192.168.1.1", Port: 80, Proto: "tcp"})
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "192.168.1.5", Port: 443, Proto: "tcp"})
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "192.168.2.1", Port: 22, Proto: "tcp"})

	// Should have 2 subnets
	if len(m.subnets) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(m.subnets))
	}

	// First subnet: 192.168.1.0/24
	sn1 := m.subnets[0]
	if sn1.Prefix != "192.168.1.0/24" {
		t.Fatalf("expected 192.168.1.0/24, got %s", sn1.Prefix)
	}
	if len(sn1.Hosts) != 2 {
		t.Fatalf("expected 2 hosts in first subnet, got %d", len(sn1.Hosts))
	}
	if sn1.Count != 3 {
		t.Fatalf("expected 3 ports in first subnet, got %d", sn1.Count)
	}

	// Hosts sorted by IP
	if sn1.Hosts[0].IPStr != "192.168.1.1" {
		t.Fatalf("expected first host 192.168.1.1, got %s", sn1.Hosts[0].IPStr)
	}
	if len(sn1.Hosts[0].Ports) != 2 {
		t.Fatalf("expected 2 ports on 192.168.1.1, got %d", len(sn1.Hosts[0].Ports))
	}

	// Ports sorted by port number
	if sn1.Hosts[0].Ports[0].Port != 22 || sn1.Hosts[0].Ports[1].Port != 80 {
		t.Fatal("ports not sorted")
	}
}

func TestTreeView_ExpandCollapse(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "22", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40
	m.treeMode = true

	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.1", Port: 22, Proto: "tcp"})
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.2", Port: 22, Proto: "tcp"})

	// Initially collapsed: 1 subnet line
	if m.treeLineCount() != 1 {
		t.Fatalf("expected 1 line (collapsed), got %d", m.treeLineCount())
	}

	// Expand subnet
	m.treeCursor = 0
	m.toggleTreeNode()
	// Now: 1 subnet + 2 hosts = 3
	if m.treeLineCount() != 3 {
		t.Fatalf("expected 3 lines (subnet expanded), got %d", m.treeLineCount())
	}

	// Expand first host
	m.treeCursor = 1
	m.toggleTreeNode()
	// Now: 1 subnet + host1(expanded, 1 port) + host2 = 4
	if m.treeLineCount() != 4 {
		t.Fatalf("expected 4 lines (host expanded), got %d", m.treeLineCount())
	}

	// Collapse subnet
	m.treeCursor = 0
	m.toggleTreeNode()
	if m.treeLineCount() != 1 {
		t.Fatalf("expected 1 line (collapsed again), got %d", m.treeLineCount())
	}
}

func TestTreeView_Render(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "22,80", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40
	m.treeMode = true

	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.1", Port: 22, Proto: "tcp"})
	m.handleEvent(ScanEvent{Type: EvtBanner, IP: "10.0.0.1", Port: 80, Proto: "tcp", Banner: "nginx", Probe: "http"})
	m.rebuildFiltered()

	v := m.View()
	if !strings.Contains(v, "10.0.0.0/24") {
		t.Fatal("tree view should contain subnet label")
	}
	if !strings.Contains(v, "expand") {
		t.Fatal("tree view help should contain 'expand'")
	}
}

// ── Sparkline tests ──────────────────────────────────────────────────

func TestSparkline_Basic(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "80", "eth0", "TCP SYN", &running)

	// Simulate some opens then tick
	m.totalOpen = 10
	m.tickSparkline()
	m.totalOpen = 25
	m.tickSparkline()
	m.totalOpen = 50
	m.tickSparkline()

	if m.sparkFilled != 3 {
		t.Fatalf("expected sparkFilled=3, got %d", m.sparkFilled)
	}

	spark := m.renderSparkline()
	if len(spark) == 0 {
		t.Fatal("expected non-empty sparkline")
	}
	// First tick: delta=10, second: delta=15, third: delta=25
	// Should have 3 unicode chars
	runes := []rune(spark)
	if len(runes) != 3 {
		t.Fatalf("expected 3 sparkline runes, got %d", len(runes))
	}
}

// ── Port histogram tests ─────────────────────────────────────────────

func TestPortHistogram(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "22,80,443", "eth0", "TCP SYN", &running)

	// Add results on different ports
	for i := 0; i < 50; i++ {
		m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.1", Port: 80, Proto: "tcp"})
	}
	for i := 0; i < 30; i++ {
		m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.1", Port: 22, Proto: "tcp"})
	}
	m.handleEvent(ScanEvent{Type: EvtOpen, IP: "10.0.0.1", Port: 443, Proto: "tcp"})

	m.rebuildTopPorts()
	if len(m.topPorts) != 3 {
		t.Fatalf("expected 3 top ports, got %d", len(m.topPorts))
	}
	// Top port should be 80 since its count is unique (50 attempts but only first is counted)
	// Actually all handleEvent for same key are deduped. Need unique keys.
	// Port 80: only 1 unique key (10.0.0.1:80/tcp), so count=1
}

func TestPortHistogram_UniqueKeys(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/24", "22,80", "eth0", "TCP SYN", &running)

	// Add unique results
	for i := 0; i < 10; i++ {
		m.handleEvent(ScanEvent{Type: EvtOpen, IP: fmt.Sprintf("10.0.0.%d", i+1), Port: 80, Proto: "tcp"})
	}
	for i := 0; i < 5; i++ {
		m.handleEvent(ScanEvent{Type: EvtOpen, IP: fmt.Sprintf("10.0.0.%d", i+1), Port: 22, Proto: "tcp"})
	}

	m.rebuildTopPorts()
	if len(m.topPorts) != 2 {
		t.Fatalf("expected 2 top ports, got %d", len(m.topPorts))
	}
	if m.topPorts[0].Port != 80 {
		t.Fatalf("expected top port=80, got %d", m.topPorts[0].Port)
	}
	if m.topPorts[0].Count != 10 {
		t.Fatalf("expected count=10, got %d", m.topPorts[0].Count)
	}
	if m.topPorts[1].Port != 22 {
		t.Fatalf("expected second port=22, got %d", m.topPorts[1].Port)
	}
}

// ── Service view tests ───────────────────────────────────────────────

func TestServiceView_Render(t *testing.T) {
	var running int32 = 1
	m := NewModel("10.0.0.0/16", "22,80", "eth0", "TCP SYN", &running)
	m.width = 120
	m.height = 40
	m.serviceMode = true

	// Add some results
	for i := 0; i < 5; i++ {
		m.handleEvent(ScanEvent{Type: EvtOpen, IP: fmt.Sprintf("10.0.%d.1", i), Port: 80, Proto: "tcp"})
		m.handleEvent(ScanEvent{Type: EvtOpen, IP: fmt.Sprintf("10.0.%d.1", i), Port: 22, Proto: "tcp"})
	}
	m.rebuildFiltered()

	v := m.View()
	if !strings.Contains(v, "HTTP") {
		t.Fatal("service view should contain 'HTTP' category")
	}
	if !strings.Contains(v, "SSH") {
		t.Fatal("service view should contain 'SSH' category")
	}
}

// ── groupKey test ────────────────────────────────────────────────────

func TestGroupKey(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.100", "192.168.1.0/24"},
		{"10.0.0.1", "10.0.0.0/24"},
		{"2001:db8::1", "2001:db8::/48"},
		{"2001:db8:abcd::1", "2001:db8:abcd::/48"},
	}
	for _, tt := range tests {
		got := groupKey(tt.ip)
		if got != tt.want {
			t.Errorf("groupKey(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}
