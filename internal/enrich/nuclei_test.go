package enrich

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func nucleiTestDir() string {
	dir := filepath.Join("tmp", "nuclei-templates")
	if _, err := os.Stat(filepath.Join(dir, "network", "detection")); err == nil {
		return dir
	}
	dir = filepath.Join("..", "..", "tmp", "nuclei-templates")
	if _, err := os.Stat(filepath.Join(dir, "network", "detection")); err == nil {
		return dir
	}
	return ""
}

func TestParseNucleiOpenSSH(t *testing.T) {
	dir := nucleiTestDir()
	if dir == "" {
		t.Skip("nuclei templates directory not found")
	}

	tmpl, err := parseNucleiFile(
		filepath.Join(dir, "network", "detection", "openssh-detect.yaml"),
		"tcp",
	)
	if err != nil {
		t.Fatalf("parseNucleiFile: %v", err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil template")
	}

	if tmpl.ID != "openssh-detect" {
		t.Errorf("ID: got %q, want openssh-detect", tmpl.ID)
	}
	if len(tmpl.Matchers) == 0 {
		t.Fatal("expected at least 1 matcher")
	}
	if len(tmpl.Extractors) == 0 {
		t.Fatal("expected at least 1 extractor")
	}
	if tmpl.Protocol != "tcp" {
		t.Errorf("protocol: got %q, want tcp", tmpl.Protocol)
	}
}

func TestNucleiMatchSSH(t *testing.T) {
	dir := nucleiTestDir()
	if dir == "" {
		t.Skip("nuclei templates directory not found")
	}

	tmpl, err := parseNucleiFile(
		filepath.Join(dir, "network", "detection", "openssh-detect.yaml"),
		"tcp",
	)
	if err != nil || tmpl == nil {
		t.Fatalf("parseNucleiFile: err=%v, tmpl=%v", err, tmpl)
	}

	banner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
	result := tmpl.Match(banner, 22)
	if result == nil {
		t.Fatal("expected match")
	}

	if len(result.NucleiIDs) == 0 || result.NucleiIDs[0] != "openssh-detect" {
		t.Errorf("nuclei IDs: got %v, want [openssh-detect]", result.NucleiIDs)
	}
}

func TestNucleiMatchNoMatch(t *testing.T) {
	dir := nucleiTestDir()
	if dir == "" {
		t.Skip("nuclei templates directory not found")
	}

	tmpl, err := parseNucleiFile(
		filepath.Join(dir, "network", "detection", "openssh-detect.yaml"),
		"tcp",
	)
	if err != nil || tmpl == nil {
		t.Fatalf("parseNucleiFile: err=%v, tmpl=%v", err, tmpl)
	}

	result := tmpl.Match("220 FTP server ready", 22)
	if result != nil {
		t.Errorf("expected no match, got %+v", result)
	}
}

func TestNucleiMatchWrongPort(t *testing.T) {
	dir := nucleiTestDir()
	if dir == "" {
		t.Skip("nuclei templates directory not found")
	}

	tmpl, err := parseNucleiFile(
		filepath.Join(dir, "network", "detection", "openssh-detect.yaml"),
		"tcp",
	)
	if err != nil || tmpl == nil {
		t.Fatalf("parseNucleiFile: err=%v, tmpl=%v", err, tmpl)
	}

	banner := "SSH-2.0-OpenSSH_8.9p1\r\n"
	result := tmpl.Match(banner, 80)
	if result != nil {
		t.Errorf("expected no match on wrong port, got %+v", result)
	}
}

func TestLoadNucleiDir(t *testing.T) {
	dir := nucleiTestDir()
	if dir == "" {
		t.Skip("nuclei templates directory not found")
	}

	templates, err := LoadNucleiDir(dir)
	if err != nil {
		t.Fatalf("LoadNucleiDir: %v", err)
	}

	if len(templates) < 50 {
		t.Errorf("expected 50+ templates, got %d", len(templates))
	}

	var tcpCount, httpCount int
	for _, tmpl := range templates {
		switch tmpl.Protocol {
		case "tcp":
			tcpCount++
		case "http":
			httpCount++
		}
	}

	if tcpCount < 20 {
		t.Errorf("expected 20+ TCP templates, got %d", tcpCount)
	}
	if httpCount < 50 {
		t.Errorf("expected 50+ HTTP templates, got %d", httpCount)
	}
	t.Logf("loaded %d templates (tcp=%d, http=%d)", len(templates), tcpCount, httpCount)
}

func TestNucleiWordMatcher(t *testing.T) {
	m := NucleiMatcher{
		Type:      "word",
		Words:     []string{"nginx"},
		Condition: "or",
	}
	if !evaluateWordMatcher(&m, "Server: nginx/1.18.0") {
		t.Error("expected word match for nginx")
	}
	if evaluateWordMatcher(&m, "Server: apache/2.4") {
		t.Error("expected no match for apache")
	}
}

func TestNucleiWordMatcherCaseInsensitive(t *testing.T) {
	m := NucleiMatcher{
		Type:            "word",
		Words:           []string{"X-Jenkins:"},
		CaseInsensitive: true,
		Condition:       "or",
	}
	if !evaluateWordMatcher(&m, "x-jenkins: 2.300") {
		t.Error("expected case-insensitive word match")
	}
}

func TestNucleiWordMatcherConditionAnd(t *testing.T) {
	m := NucleiMatcher{
		Type:      "word",
		Words:     []string{"OK ", "IMAP4rev1"},
		Condition: "and",
	}
	if !evaluateWordMatcher(&m, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.") {
		t.Error("expected AND match when both present")
	}
	if evaluateWordMatcher(&m, "* OK Dovecot ready.") {
		t.Error("expected no match when only one word present")
	}
}

func TestGetMatchPart(t *testing.T) {
	full := "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html>body</html>"

	header := getMatchPart(full, "header")
	if header != "HTTP/1.1 200 OK\r\nServer: nginx" {
		t.Errorf("header: got %q", header)
	}

	body := getMatchPart(full, "body")
	if body != "<html>body</html>" {
		t.Errorf("body: got %q", body)
	}

	all := getMatchPart(full, "")
	if all != full {
		t.Error("empty part should return full banner")
	}
}

func TestNucleiMatchersConditionAnd(t *testing.T) {
	tmpl := &NucleiTemplate{
		ID:        "test-and",
		MatchCond: "and",
		Matchers: []NucleiMatcher{
			{
				Type:      "regex",
				Patterns:  []*regexp.Regexp{regexp.MustCompile(`nginx/[0-9.]+`)},
				Part:      "header",
				Condition: "or",
			},
			{Type: "status"}, // always passes
		},
	}

	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
	result := tmpl.Match(banner, 80)
	if result == nil {
		t.Fatal("expected AND match")
	}
}
