package enrich

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FingerprintDB represents one recog XML file (e.g. ssh_banners.xml).
type FingerprintDB struct {
	Name       string  // matches attr: "http_header.server", "ssh.banner", etc.
	Protocol   string  // "http", "ssh", "ftp", etc.
	Preference float64 // 0.0–1.0
	Entries    []Fingerprint
}

// Fingerprint is a single pattern within a FingerprintDB.
type Fingerprint struct {
	Pattern     *regexp.Regexp
	Description string
	Params      []Param
}

// Param defines a value extracted from a match.
// pos=0: static value. pos>0: capture group index.
type Param struct {
	Pos   int
	Name  string
	Value string // static value (pos=0) or CPE template with {placeholders}
}

// XML structures for parsing recog format.
type xmlFingerprints struct {
	XMLName    xml.Name         `xml:"fingerprints"`
	Matches    string           `xml:"matches,attr"`
	Protocol   string           `xml:"protocol,attr"`
	DBType     string           `xml:"database_type,attr"`
	Preference float64          `xml:"preference,attr"`
	Entries    []xmlFingerprint `xml:"fingerprint"`
}

type xmlFingerprint struct {
	Pattern     string     `xml:"pattern,attr"`
	Flags       string     `xml:"flags,attr"`
	Description string     `xml:"description"`
	Params      []xmlParam `xml:"param"`
}

type xmlParam struct {
	Pos   int    `xml:"pos,attr"`
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// LoadRecogDir parses all XML files in dir, compiles regexes, and returns a
// map keyed by the "matches" attribute (e.g. "ssh.banner").
func LoadRecogDir(dir string) (map[string]*FingerprintDB, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.xml"))
	if err != nil {
		return nil, fmt.Errorf("glob recog dir: %w", err)
	}

	dbs := make(map[string]*FingerprintDB, len(files))
	var skipped int

	for _, fpath := range files {
		base := filepath.Base(fpath)
		// Skip non-banner files
		if base == "favicons.xml" || base == "fingerprints.xsd" {
			continue
		}

		db, err := parseRecogFile(fpath)
		if err != nil {
			skipped++
			continue
		}
		if len(db.Entries) == 0 {
			continue
		}
		// If no matches attr, use filename stem (e.g. "telnet_banners")
		if db.Name == "" {
			db.Name = strings.TrimSuffix(filepath.Base(fpath), ".xml")
		}
		dbs[db.Name] = db
	}

	if len(dbs) == 0 {
		return nil, fmt.Errorf("no usable recog databases found in %s (skipped %d)", dir, skipped)
	}
	return dbs, nil
}

func parseRecogFile(path string) (*FingerprintDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var xfp xmlFingerprints
	if err := xml.Unmarshal(data, &xfp); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}

	db := &FingerprintDB{
		Name:       xfp.Matches,
		Protocol:   xfp.Protocol,
		Preference: xfp.Preference,
		Entries:    make([]Fingerprint, 0, len(xfp.Entries)),
	}

	for _, xe := range xfp.Entries {
		pat := xe.Pattern
		if pat == "" {
			continue
		}

		// Handle flags
		flags := strings.ToUpper(xe.Flags)
		prefix := ""
		if strings.Contains(flags, "REG_ICASE") {
			prefix += "(?i)"
		}
		if strings.Contains(flags, "REG_MULTILINE") {
			prefix += "(?ms)"
		}

		re, err := regexp.Compile(prefix + pat)
		if err != nil {
			continue // skip invalid patterns
		}

		params := make([]Param, len(xe.Params))
		for i, xp := range xe.Params {
			params[i] = Param{
				Pos:   xp.Pos,
				Name:  xp.Name,
				Value: xp.Value,
			}
		}

		db.Entries = append(db.Entries, Fingerprint{
			Pattern:     re,
			Description: xe.Description,
			Params:      params,
		})
	}

	return db, nil
}

// Match tests input against all fingerprints. First match wins.
// Returns nil if nothing matches.
func (db *FingerprintDB) Match(input string) *MatchResult {
	for i := range db.Entries {
		fp := &db.Entries[i]
		m := fp.Pattern.FindStringSubmatch(input)
		if m == nil {
			continue
		}
		return buildRecogResult(db, fp, m)
	}
	return nil
}

func buildRecogResult(db *FingerprintDB, fp *Fingerprint, groups []string) *MatchResult {
	res := &MatchResult{
		Source:      "recog:" + db.Name,
		Description: fp.Description,
		Confidence:  db.Preference,
	}

	// Collect resolved param values for CPE template substitution.
	resolved := make(map[string]string, len(fp.Params))

	for _, p := range fp.Params {
		var val string
		if p.Pos == 0 {
			val = p.Value
		} else if p.Pos < len(groups) {
			val = groups[p.Pos]
		}
		if val == "" {
			continue
		}
		resolved[p.Name] = val
		applyParam(res, p.Name, val)
	}

	// Second pass: resolve CPE templates with {placeholders}.
	if res.ServiceCPE != "" && strings.Contains(res.ServiceCPE, "{") {
		res.ServiceCPE = expandCPETemplate(res.ServiceCPE, resolved)
	}

	return res
}

func applyParam(res *MatchResult, name, value string) {
	switch name {
	case "service.vendor":
		res.ServiceVendor = value
	case "service.product":
		res.ServiceProduct = value
	case "service.version":
		res.ServiceVersion = value
	case "service.cpe23":
		res.ServiceCPE = value
	case "os.vendor":
		res.OSVendor = value
	case "os.product":
		res.OSProduct = value
	case "os.version":
		res.OSVersion = value
	case "os.family":
		res.OSFamily = value
	case "os.device":
		res.OSDevice = value
	case "os.cpe23":
		if res.Extra == nil {
			res.Extra = make(map[string]string)
		}
		res.Extra["os.cpe23"] = value
	case "hw.vendor":
		res.HWVendor = value
	case "hw.product":
		res.HWProduct = value
	default:
		if res.Extra == nil {
			res.Extra = make(map[string]string)
		}
		res.Extra[name] = value
	}
}

// expandCPETemplate replaces {key} placeholders in a CPE string.
func expandCPETemplate(tpl string, vals map[string]string) string {
	result := tpl
	for k, v := range vals {
		result = strings.ReplaceAll(result, "{"+k+"}", v)
	}
	return result
}

// RecogDBCount returns the number of fingerprint entries across all DBs.
func RecogDBCount(dbs map[string]*FingerprintDB) int {
	total := 0
	for _, db := range dbs {
		total += len(db.Entries)
	}
	return total
}

// LoadRecogFile is exported for testing individual files.
func LoadRecogFile(path string) (*FingerprintDB, error) {
	return parseRecogFile(path)
}
