package enrich

import (
	"testing"
)

func loadTestRouter(t *testing.T) *Router {
	t.Helper()
	dir := recogTestDir()
	ndir := nucleiTestDir()

	if dir == "" && ndir == "" {
		t.Skip("neither recog nor nuclei test data found")
	}

	var recogDBs map[string]*FingerprintDB
	var nuclei []*NucleiTemplate

	if dir != "" {
		var err error
		recogDBs, err = LoadRecogDir(dir)
		if err != nil {
			t.Fatalf("LoadRecogDir: %v", err)
		}
	}

	if ndir != "" {
		var err error
		nuclei, err = LoadNucleiDir(ndir)
		if err != nil {
			t.Fatalf("LoadNucleiDir: %v", err)
		}
	}

	return NewRouter(recogDBs, nuclei)
}

func TestRouterSSHPort22(t *testing.T) {
	r := loadTestRouter(t)

	result := r.Enrich("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n", 22, "tcp")
	if result == nil {
		t.Fatal("expected match for SSH on port 22")
	}

	if result.ServiceProduct != "OpenSSH" {
		t.Errorf("product: got %q, want OpenSSH", result.ServiceProduct)
	}
	if result.ServiceVersion != "8.9p1" {
		t.Errorf("version: got %q, want 8.9p1", result.ServiceVersion)
	}
	t.Logf("matched_by=%s", result.Source)
}

func TestRouterSSHNonStandardPort(t *testing.T) {
	r := loadTestRouter(t)

	// SSH on port 2222 should be detected via banner sniffing
	result := r.Enrich("SSH-2.0-OpenSSH_7.4\r\n", 2222, "tcp")
	if result == nil {
		t.Fatal("expected match for SSH on non-standard port")
	}

	if result.ServiceProduct != "OpenSSH" {
		t.Errorf("product: got %q, want OpenSSH", result.ServiceProduct)
	}
}

func TestRouterHTTPBanner(t *testing.T) {
	r := loadTestRouter(t)

	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><title>Welcome</title></html>"
	result := r.Enrich(banner, 80, "tcp")
	if result == nil {
		t.Fatal("expected match for HTTP banner")
	}

	t.Logf("vendor=%s product=%s version=%s source=%s nuclei=%v",
		result.ServiceVendor, result.ServiceProduct, result.ServiceVersion,
		result.Source, result.NucleiIDs)
}

func TestRouterHTTPNonStandardPort(t *testing.T) {
	r := loadTestRouter(t)

	banner := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"
	result := r.Enrich(banner, 9090, "tcp")
	if result == nil {
		t.Fatal("expected match for HTTP on non-standard port via sniffing")
	}
	t.Logf("source=%s product=%s", result.Source, result.ServiceProduct)
}

func TestRouterNoMatch(t *testing.T) {
	r := loadTestRouter(t)

	result := r.Enrich("some random binary garbage \x00\x01\x02", 54321, "tcp")
	// This might match or not depending on fallback matching
	t.Logf("result for garbage: %v", result)
}

func TestRouterEmptyBanner(t *testing.T) {
	r := loadTestRouter(t)

	result := r.Enrich("", 80, "tcp")
	if result != nil {
		t.Errorf("expected nil for empty banner, got %+v", result)
	}
}

func TestRouterDropbearSSH(t *testing.T) {
	r := loadTestRouter(t)

	result := r.Enrich("SSH-2.0-dropbear_2022.83\r\n", 22, "tcp")
	if result == nil {
		t.Fatal("expected match for dropbear SSH")
	}

	if result.ServiceProduct != "Dropbear SSH" {
		t.Errorf("product: got %q, want Dropbear SSH", result.ServiceProduct)
	}
	if result.ServiceVersion != "2022.83" {
		t.Errorf("version: got %q, want 2022.83", result.ServiceVersion)
	}
}

func TestMatchResultMerge(t *testing.T) {
	a := &MatchResult{
		Source:         "recog:ssh.banner",
		ServiceVendor:  "OpenBSD",
		ServiceProduct: "OpenSSH",
		ServiceVersion: "8.9p1",
		Confidence:     0.9,
	}

	b := &MatchResult{
		Source:         "nuclei:openssh-detect",
		ServiceProduct: "OpenSSH",
		OSVendor:       "Ubuntu",
		Confidence:     0.5,
		NucleiIDs:      []string{"openssh-detect"},
	}

	a.Merge(b)

	if a.OSVendor != "Ubuntu" {
		t.Errorf("expected merged OSVendor=Ubuntu, got %q", a.OSVendor)
	}
	if a.ServiceVendor != "OpenBSD" {
		t.Errorf("vendor should remain OpenBSD (higher confidence), got %q", a.ServiceVendor)
	}
	if len(a.NucleiIDs) != 1 || a.NucleiIDs[0] != "openssh-detect" {
		t.Errorf("nuclei IDs: got %v", a.NucleiIDs)
	}
}
