package enrich

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// NucleiTemplate represents a parsed nuclei detection template.
type NucleiTemplate struct {
	ID        string
	Name      string
	Vendor    string   // from info.metadata.vendor
	Product   string   // from info.metadata.product
	CPE       string   // from info.classification.cpe
	Tags      string
	Ports     []uint16 // from tcp[].port
	Protocol  string   // "tcp" or "http"
	Matchers  []NucleiMatcher
	MatchCond string // "and" (default) or "or"
	Extractors []NucleiExtractor

	// Quick-reject filter for fast banner pre-screening.
	// Each entry in quickRejectGroups corresponds to one matcher's literals.
	// AND-condition: if ANY group's literals are all missing → reject.
	// OR-condition: if EVERY group's literals are all missing → reject.
	//   (only valid when every matcher has at least one extractable literal)
	quickRejectGroups [][]string // [matcher_index][literal_index] lowercase
	quickRejectIsAnd  bool
	quickRejectValid  bool // false if any non-status matcher has no literals (OR-mode only)
}

// NucleiMatcher is a compiled matcher from a nuclei template.
type NucleiMatcher struct {
	Type            string           // "regex" or "word"
	Part            string           // "body", "header", "" (default: full banner)
	Patterns        []*regexp.Regexp // compiled regex patterns
	PatternLiterals []string         // lowercase literals extracted per-pattern for fast pre-filter
	Words           []string         // for word matchers
	CaseInsensitive bool
	Condition       string // "and" or "or" (default "or")
}

// NucleiExtractor extracts data from a matched banner.
type NucleiExtractor struct {
	Type    string // "regex"
	Group   int
	Name    string
	Pattern *regexp.Regexp
}

// YAML structures for parsing nuclei templates.
type yamlTemplate struct {
	ID   string       `yaml:"id"`
	Info yamlInfo     `yaml:"info"`
	TCP  []yamlTCP    `yaml:"tcp"`
	HTTP []yamlHTTP   `yaml:"http"`
}

type yamlInfo struct {
	Name           string             `yaml:"name"`
	Tags           string             `yaml:"tags"`
	Classification yamlClassification `yaml:"classification"`
	Metadata       map[string]interface{} `yaml:"metadata"`
}

type yamlClassification struct {
	CPE string `yaml:"cpe"`
}

type yamlTCP struct {
	Host           []string         `yaml:"host"`
	Port           interface{}      `yaml:"port"` // can be int or string "80,443"
	Inputs         []yamlInput      `yaml:"inputs"`
	Matchers       []yamlMatcher    `yaml:"matchers"`
	MatchersCond   string           `yaml:"matchers-condition"`
	Extractors     []yamlExtractor  `yaml:"extractors"`
}

type yamlHTTP struct {
	Method       string          `yaml:"method"`
	Path         []string        `yaml:"path"`
	Matchers     []yamlMatcher   `yaml:"matchers"`
	MatchersCond string          `yaml:"matchers-condition"`
	Extractors   []yamlExtractor `yaml:"extractors"`
}

type yamlInput struct {
	Data string `yaml:"data"`
	Type string `yaml:"type"`
}

type yamlMatcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"`
	Regex           []string `yaml:"regex"`
	Words           []string `yaml:"words"`
	Status          []int    `yaml:"status"`
	DSL             []string `yaml:"dsl"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	Condition       string   `yaml:"condition"`
}

type yamlExtractor struct {
	Type  string   `yaml:"type"`
	Group int      `yaml:"group"`
	Name  string   `yaml:"name"`
	Regex []string `yaml:"regex"`
	Part  string   `yaml:"part"`
	KVal  []string `yaml:"kval"`
}

// LoadNucleiDir walks dir for YAML templates, parses and compiles them.
// It loads from network/detection/ and http/technologies/ subdirectories.
func LoadNucleiDir(dir string) ([]*NucleiTemplate, error) {
	var templates []*NucleiTemplate

	// Load TCP templates from network/detection/
	tcpDir := filepath.Join(dir, "network", "detection")
	if info, err := os.Stat(tcpDir); err == nil && info.IsDir() {
		tcp, err := loadNucleiSubdir(tcpDir, "tcp")
		if err != nil {
			return nil, fmt.Errorf("load nuclei tcp: %w", err)
		}
		templates = append(templates, tcp...)
	}

	// Load HTTP templates from http/technologies/
	httpDir := filepath.Join(dir, "http", "technologies")
	if info, err := os.Stat(httpDir); err == nil && info.IsDir() {
		http, err := loadNucleiSubdir(httpDir, "http")
		if err != nil {
			return nil, fmt.Errorf("load nuclei http: %w", err)
		}
		templates = append(templates, http...)
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("no usable nuclei templates found in %s", dir)
	}
	return templates, nil
}

func loadNucleiSubdir(dir, proto string) ([]*NucleiTemplate, error) {
	var templates []*NucleiTemplate

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		t, err := parseNucleiFile(path, proto)
		if err != nil || t == nil {
			return nil // skip unparseable or unusable templates
		}
		templates = append(templates, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return templates, nil
}

func parseNucleiFile(path, defaultProto string) (*NucleiTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var yt yamlTemplate
	if err := yaml.Unmarshal(data, &yt); err != nil {
		return nil, err
	}

	if yt.ID == "" {
		return nil, nil
	}

	t := &NucleiTemplate{
		ID:       yt.ID,
		Name:     yt.Info.Name,
		CPE:      yt.Info.Classification.CPE,
		Tags:     yt.Info.Tags,
		Protocol: defaultProto,
	}

	// Extract vendor/product from metadata
	if yt.Info.Metadata != nil {
		if v, ok := yt.Info.Metadata["vendor"].(string); ok {
			t.Vendor = v
		}
		if p, ok := yt.Info.Metadata["product"].(string); ok {
			t.Product = p
		}
	}

	switch defaultProto {
	case "tcp":
		if len(yt.TCP) == 0 {
			return nil, nil
		}
		tc := &yt.TCP[0]

		// Skip hex-input templates (active probing only)
		for _, inp := range tc.Inputs {
			if inp.Type == "hex" {
				return nil, nil
			}
		}

		t.Ports = parsePorts(tc.Port)
		t.MatchCond = tc.MatchersCond
		if t.MatchCond == "" {
			t.MatchCond = "or"
		}

		matchers, ok := compileMatchers(tc.Matchers)
		if !ok {
			return nil, nil // no usable matchers
		}
		t.Matchers = matchers
		t.Extractors = compileExtractors(tc.Extractors)

	case "http":
		if len(yt.HTTP) == 0 {
			return nil, nil
		}
		hc := &yt.HTTP[0]

		// Skip templates with non-BaseURL paths (require crawling)
		for _, p := range hc.Path {
			if p != "{{BaseURL}}" && p != "{{BaseURL}}/" {
				return nil, nil
			}
		}

		t.MatchCond = hc.MatchersCond
		if t.MatchCond == "" {
			t.MatchCond = "or"
		}

		matchers, ok := compileMatchers(hc.Matchers)
		if !ok {
			return nil, nil
		}
		t.Matchers = matchers
		t.Extractors = compileExtractors(hc.Extractors)
	}

	// Build quick-reject literals for fast filtering.
	t.buildQuickReject()

	return t, nil
}

func compileMatchers(yms []yamlMatcher) ([]NucleiMatcher, bool) {
	var matchers []NucleiMatcher
	hasUsable := false

	for _, ym := range yms {
		switch ym.Type {
		case "regex":
			patterns := make([]*regexp.Regexp, 0, len(ym.Regex))
			literals := make([]string, 0, len(ym.Regex))
			for _, r := range ym.Regex {
				re, err := regexp.Compile(r)
				if err != nil {
					continue
				}
				patterns = append(patterns, re)
				lit := extractRegexLiteral(r)
				if len(lit) >= 3 {
					literals = append(literals, strings.ToLower(lit))
				} else {
					literals = append(literals, "") // no usable literal
				}
			}
			if len(patterns) == 0 {
				continue
			}
			hasUsable = true
			cond := ym.Condition
			if cond == "" {
				cond = "or"
			}
			matchers = append(matchers, NucleiMatcher{
				Type:            "regex",
				Part:            ym.Part,
				Patterns:        patterns,
				PatternLiterals: literals,
				Condition:       cond,
			})

		case "word":
			if len(ym.Words) == 0 {
				continue
			}
			hasUsable = true
			cond := ym.Condition
			if cond == "" {
				cond = "or"
			}
			matchers = append(matchers, NucleiMatcher{
				Type:            "word",
				Part:            ym.Part,
				Words:           ym.Words,
				CaseInsensitive: ym.CaseInsensitive,
				Condition:       cond,
			})

		case "status":
			// We skip status matchers (we don't have status codes isolated).
			// Add a placeholder so matchers-condition: and doesn't fail.
			matchers = append(matchers, NucleiMatcher{
				Type: "status",
			})

		case "dsl":
			// Skip DSL matchers.
			continue

		default:
			continue
		}
	}

	return matchers, hasUsable
}

func compileExtractors(yes []yamlExtractor) []NucleiExtractor {
	var extractors []NucleiExtractor
	for _, ye := range yes {
		if ye.Type != "regex" || len(ye.Regex) == 0 {
			continue
		}
		re, err := regexp.Compile(ye.Regex[0])
		if err != nil {
			continue
		}
		extractors = append(extractors, NucleiExtractor{
			Type:    "regex",
			Group:   ye.Group,
			Name:    ye.Name,
			Pattern: re,
		})
	}
	return extractors
}

func parsePorts(v interface{}) []uint16 {
	switch p := v.(type) {
	case int:
		if p > 0 && p <= 65535 {
			return []uint16{uint16(p)}
		}
	case string:
		return parsePortString(p)
	case []interface{}:
		var ports []uint16
		for _, item := range p {
			switch iv := item.(type) {
			case int:
				if iv > 0 && iv <= 65535 {
					ports = append(ports, uint16(iv))
				}
			case string:
				ports = append(ports, parsePortString(iv)...)
			}
		}
		return ports
	}
	return nil
}

func parsePortString(s string) []uint16 {
	var ports []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err == nil && n > 0 && n <= 65535 {
			ports = append(ports, uint16(n))
		}
	}
	return ports
}

// buildQuickReject extracts literal strings from matchers for fast pre-filtering.
func (t *NucleiTemplate) buildQuickReject() {
	t.quickRejectIsAnd = t.MatchCond == "and"
	t.quickRejectValid = true

	for _, m := range t.Matchers {
		if m.Type == "status" {
			continue // status matchers always pass, skip
		}

		var lits []string
		switch m.Type {
		case "word":
			for _, w := range m.Words {
				lit := strings.ToLower(w)
				if len(lit) >= 2 {
					lits = append(lits, lit)
				}
			}
		case "regex":
			for _, re := range m.Patterns {
				lit := extractRegexLiteral(re.String())
				if len(lit) >= 4 {
					lits = append(lits, strings.ToLower(lit))
				}
			}
		}

		if len(lits) == 0 {
			// This matcher has no extractable literal.
			// For OR: can't reject (this matcher might still match anything).
			if !t.quickRejectIsAnd {
				t.quickRejectValid = false
			}
			// For AND: skip this group (we can't reject based on it,
			// but other groups may still allow rejection).
			continue
		}

		t.quickRejectGroups = append(t.quickRejectGroups, lits)
	}
}

// extractRegexLiteral finds the longest run of non-meta characters in a regex.
func extractRegexLiteral(pattern string) string {
	// Strip leading flags like (?i)
	for strings.HasPrefix(pattern, "(?") {
		if idx := strings.IndexByte(pattern, ')'); idx >= 0 {
			pattern = pattern[idx+1:]
		} else {
			break
		}
	}

	var best string
	var cur strings.Builder
	escaped := false

	for _, ch := range pattern {
		if escaped {
			// \w, \d, \s etc are not literal
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' {
				if cur.Len() > len(best) {
					best = cur.String()
				}
				cur.Reset()
			} else {
				cur.WriteRune(ch)
			}
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		// Regex metacharacters
		if strings.ContainsRune("[](){}.*+?|^$", ch) {
			if cur.Len() > len(best) {
				best = cur.String()
			}
			cur.Reset()
			continue
		}
		cur.WriteRune(ch)
	}
	if cur.Len() > len(best) {
		best = cur.String()
	}
	return best
}

// quickReject returns true if the banner definitely won't match this template.
func (t *NucleiTemplate) quickReject(bannerLower string) bool {
	if len(t.quickRejectGroups) == 0 {
		return false // no literals to check, can't reject
	}

	if t.quickRejectIsAnd {
		// AND: if ANY group has all its literals missing, that matcher can't
		// match → the AND fails → reject.
		for _, group := range t.quickRejectGroups {
			found := false
			for _, lit := range group {
				if strings.Contains(bannerLower, lit) {
					found = true
					break
				}
			}
			if !found {
				return true // this matcher's group has no literals present → reject
			}
		}
		return false
	}

	// OR: if EVERY group has all its literals missing, no matcher can match → reject.
	// But only if quickRejectValid (every non-status matcher has at least one literal).
	if !t.quickRejectValid {
		return false
	}
	for _, group := range t.quickRejectGroups {
		for _, lit := range group {
			if strings.Contains(bannerLower, lit) {
				return false // this group has a literal present → matcher might match
			}
		}
	}
	return true // no group has any literal present → reject
}

// Match evaluates the template's matchers against a banner.
// Returns nil if no match.
func (t *NucleiTemplate) Match(banner string, port uint16) *MatchResult {
	return t.MatchWithLower(banner, "", port)
}

// MatchWithLower is like Match but accepts a precomputed lowercase banner
// for quick-reject filtering. If bannerLower is empty, it's computed on demand.
func (t *NucleiTemplate) MatchWithLower(banner, bannerLower string, port uint16) *MatchResult {
	// Port filtering for TCP templates
	if len(t.Ports) > 0 {
		found := false
		for _, p := range t.Ports {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}

	// Quick reject: check if banner contains required literal strings.
	if len(t.quickRejectGroups) > 0 {
		if bannerLower == "" {
			bannerLower = strings.ToLower(banner)
		}
		if t.quickReject(bannerLower) {
			return nil
		}
	}

	if bannerLower == "" {
		bannerLower = strings.ToLower(banner)
	}

	if !t.evaluateMatchers(banner, bannerLower) {
		return nil
	}

	res := &MatchResult{
		Source:         "nuclei:" + t.ID,
		ServiceVendor:  t.Vendor,
		ServiceProduct: t.Product,
		ServiceCPE:     t.CPE,
		Description:    t.Name,
		Confidence:     0.5,
		NucleiIDs:      []string{t.ID},
	}

	// Run extractors
	for _, ext := range t.Extractors {
		m := ext.Pattern.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		var val string
		if ext.Group < len(m) {
			val = m[ext.Group]
		} else if len(m) > 0 {
			val = m[0]
		}
		if val == "" {
			continue
		}

		switch ext.Name {
		case "version":
			if res.ServiceVersion == "" {
				res.ServiceVersion = val
			}
		default:
			if res.ServiceVersion == "" {
				res.ServiceVersion = val
			}
		}
	}

	return res
}

func (t *NucleiTemplate) evaluateMatchers(banner, bannerLower string) bool {
	if len(t.Matchers) == 0 {
		return false
	}

	isAnd := t.MatchCond == "and"

	for _, m := range t.Matchers {
		matched := evaluateSingleMatcher(&m, banner, bannerLower)

		if isAnd && !matched {
			return false
		}
		if !isAnd && matched {
			return true
		}
	}

	return isAnd // AND: all passed; OR: none passed
}

func evaluateSingleMatcher(m *NucleiMatcher, banner, bannerLower string) bool {
	switch m.Type {
	case "status":
		return true

	case "regex":
		input := getMatchPart(banner, m.Part)
		inputLower := getMatchPart(bannerLower, m.Part)
		return evaluateRegexMatcher(m, input, inputLower)

	case "word":
		input := getMatchPart(banner, m.Part)
		return evaluateWordMatcher(m, input)
	}
	return false
}

func getMatchPart(banner, part string) string {
	switch part {
	case "header":
		if idx := strings.Index(banner, "\r\n\r\n"); idx >= 0 {
			return banner[:idx]
		}
		// Try LF-only
		if idx := strings.Index(banner, "\n\n"); idx >= 0 {
			return banner[:idx]
		}
		return banner
	case "body":
		if idx := strings.Index(banner, "\r\n\r\n"); idx >= 0 {
			return banner[idx+4:]
		}
		if idx := strings.Index(banner, "\n\n"); idx >= 0 {
			return banner[idx+2:]
		}
		return ""
	default:
		return banner
	}
}

func evaluateRegexMatcher(m *NucleiMatcher, input, inputLower string) bool {
	isAnd := m.Condition == "and"

	for i, re := range m.Patterns {
		// Per-pattern literal pre-filter: if the literal isn't in the input,
		// the regex can't match. ~10x faster than running the full regex.
		if i < len(m.PatternLiterals) && m.PatternLiterals[i] != "" {
			if !strings.Contains(inputLower, m.PatternLiterals[i]) {
				if isAnd {
					return false
				}
				continue // OR: skip this pattern, try next
			}
		}

		if re.MatchString(input) {
			if !isAnd {
				return true
			}
		} else {
			if isAnd {
				return false
			}
		}
	}
	return isAnd
}

func evaluateWordMatcher(m *NucleiMatcher, input string) bool {
	isAnd := m.Condition == "and"

	checkInput := input
	if m.CaseInsensitive {
		checkInput = strings.ToLower(input)
	}

	for _, word := range m.Words {
		checkWord := word
		if m.CaseInsensitive {
			checkWord = strings.ToLower(word)
		}
		if strings.Contains(checkInput, checkWord) {
			if !isAnd {
				return true
			}
		} else {
			if isAnd {
				return false
			}
		}
	}
	return isAnd
}
