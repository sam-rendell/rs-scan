package enrich

import (
	"os"
	"path/filepath"
	"testing"
)

func recogTestDir() string {
	// Check standard location
	dir := filepath.Join("tmp", "recog", "xml")
	if _, err := os.Stat(filepath.Join(dir, "ssh_banners.xml")); err == nil {
		return dir
	}
	// Check from repo root
	dir = filepath.Join("..", "..", "tmp", "recog", "xml")
	if _, err := os.Stat(filepath.Join(dir, "ssh_banners.xml")); err == nil {
		return dir
	}
	return ""
}

func TestLoadRecogSSHBanners(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	db, err := LoadRecogFile(filepath.Join(dir, "ssh_banners.xml"))
	if err != nil {
		t.Fatalf("LoadRecogFile: %v", err)
	}
	if db.Name != "ssh.banner" {
		t.Errorf("expected name ssh.banner, got %s", db.Name)
	}
	if db.Protocol != "ssh" {
		t.Errorf("expected protocol ssh, got %s", db.Protocol)
	}
	if len(db.Entries) < 100 {
		t.Errorf("expected 100+ fingerprints, got %d", len(db.Entries))
	}
	if db.Preference < 0.5 {
		t.Errorf("expected preference >= 0.5, got %f", db.Preference)
	}
}

func TestRecogMatchOpenSSHUbuntu(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	db, err := LoadRecogFile(filepath.Join(dir, "ssh_banners.xml"))
	if err != nil {
		t.Fatalf("LoadRecogFile: %v", err)
	}

	// The SSH software string (after SSH-2.0-)
	result := db.Match("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
	if result == nil {
		t.Fatal("expected match for OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
	}

	if result.ServiceVendor != "OpenBSD" {
		t.Errorf("vendor: got %q, want OpenBSD", result.ServiceVendor)
	}
	if result.ServiceProduct != "OpenSSH" {
		t.Errorf("product: got %q, want OpenSSH", result.ServiceProduct)
	}
	if result.ServiceVersion != "8.9p1" {
		t.Errorf("version: got %q, want 8.9p1", result.ServiceVersion)
	}
	if result.OSVendor != "Ubuntu" {
		t.Errorf("os vendor: got %q, want Ubuntu", result.OSVendor)
	}
}

func TestRecogMatchDropbear(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	db, err := LoadRecogFile(filepath.Join(dir, "ssh_banners.xml"))
	if err != nil {
		t.Fatalf("LoadRecogFile: %v", err)
	}

	result := db.Match("dropbear_2022.83")
	if result == nil {
		t.Fatal("expected match for dropbear_2022.83")
	}

	if result.ServiceVendor != "Dropbear SSH Project" {
		t.Errorf("vendor: got %q, want Dropbear SSH Project", result.ServiceVendor)
	}
	if result.ServiceProduct != "Dropbear SSH" {
		t.Errorf("product: got %q, want Dropbear SSH", result.ServiceProduct)
	}
	if result.ServiceVersion != "2022.83" {
		t.Errorf("version: got %q, want 2022.83", result.ServiceVersion)
	}
}

func TestRecogCPETemplateSubstitution(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	db, err := LoadRecogFile(filepath.Join(dir, "ssh_banners.xml"))
	if err != nil {
		t.Fatalf("LoadRecogFile: %v", err)
	}

	result := db.Match("OpenSSH_5.9p1")
	if result == nil {
		t.Fatal("expected match for OpenSSH_5.9p1")
	}

	want := "cpe:/a:openbsd:openssh:5.9p1"
	if result.ServiceCPE != want {
		t.Errorf("CPE: got %q, want %q", result.ServiceCPE, want)
	}
}

func TestRecogNoMatch(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	db, err := LoadRecogFile(filepath.Join(dir, "ssh_banners.xml"))
	if err != nil {
		t.Fatalf("LoadRecogFile: %v", err)
	}

	result := db.Match("totally_unknown_server_12345")
	if result != nil {
		t.Errorf("expected nil for unknown banner, got %+v", result)
	}
}

func TestRecogREG_ICASE(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	// ftp_banners.xml has many REG_ICASE patterns
	db, err := LoadRecogFile(filepath.Join(dir, "ftp_banners.xml"))
	if err != nil {
		t.Fatalf("LoadRecogFile: %v", err)
	}

	// Verify at least some entries compiled with case-insensitive flag
	hasCaseInsensitive := false
	for _, e := range db.Entries {
		pat := e.Pattern.String()
		if len(pat) >= 4 && pat[:4] == "(?i)" {
			hasCaseInsensitive = true
			break
		}
	}
	if !hasCaseInsensitive {
		t.Error("expected some case-insensitive patterns in ftp_banners.xml")
	}
}

func TestLoadRecogDir(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	dbs, err := LoadRecogDir(dir)
	if err != nil {
		t.Fatalf("LoadRecogDir: %v", err)
	}

	if len(dbs) < 10 {
		t.Errorf("expected 10+ databases, got %d", len(dbs))
	}

	// Check key databases exist
	for _, name := range []string{"ssh.banner", "http_header.server", "ftp.banner", "smtp.banner"} {
		if _, ok := dbs[name]; !ok {
			t.Errorf("missing expected database: %s", name)
		}
	}

	total := RecogDBCount(dbs)
	if total < 1000 {
		t.Errorf("expected 1000+ total fingerprints, got %d", total)
	}
}

func TestRecogMatchHTTPServer(t *testing.T) {
	dir := recogTestDir()
	if dir == "" {
		t.Skip("recog XML directory not found")
	}

	db, err := LoadRecogFile(filepath.Join(dir, "http_servers.xml"))
	if err != nil {
		t.Fatalf("LoadRecogFile: %v", err)
	}

	result := db.Match("Transmission")
	if result == nil {
		t.Fatal("expected match for Transmission")
	}
	if result.ServiceVendor != "TransmissionBT" {
		t.Errorf("vendor: got %q, want TransmissionBT", result.ServiceVendor)
	}
}
