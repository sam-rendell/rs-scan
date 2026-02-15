package enrich

import (
	"regexp"
	"strings"
)

// Router dispatches banners to the correct recog DBs and nuclei templates
// based on port and banner content sniffing.
type Router struct {
	recogDBs        map[string]*FingerprintDB
	nucleiTCPNoPort []*NucleiTemplate         // TCP templates with no port constraint
	nucleiHTTPNoPort []*NucleiTemplate        // HTTP templates with no port constraint
	portIndex       map[uint16][]*NucleiTemplate // nuclei templates indexed by port
}

// NewRouter builds a Router from loaded recog databases and nuclei templates.
func NewRouter(recogDBs map[string]*FingerprintDB, nuclei []*NucleiTemplate) *Router {
	r := &Router{
		recogDBs:  recogDBs,
		portIndex: make(map[uint16][]*NucleiTemplate),
	}

	for _, t := range nuclei {
		if len(t.Ports) > 0 {
			for _, p := range t.Ports {
				r.portIndex[p] = append(r.portIndex[p], t)
			}
		} else {
			// No port constraint — bucket by protocol
			switch t.Protocol {
			case "tcp":
				r.nucleiTCPNoPort = append(r.nucleiTCPNoPort, t)
			case "http":
				r.nucleiHTTPNoPort = append(r.nucleiHTTPNoPort, t)
			}
		}
	}

	return r
}

var (
	httpServerRe     = regexp.MustCompile(`(?i)Server:\s*(.+?)[\r\n]`)
	httpXPoweredByRe = regexp.MustCompile(`(?i)X-Powered-By:\s*(.+?)[\r\n]`)
	htmlTitleRe      = regexp.MustCompile(`(?i)<title>\s*(.+?)\s*</title>`)
	mysqlVersionRe   = regexp.MustCompile(`[\x00-\x1f]([0-9]+\.[0-9]+\.[0-9]+[^\x00]*)`)
)

// Enrich matches a banner against all loaded sources and returns merged results.
// Returns nil if no match. Safe for concurrent use from multiple goroutines.
func (r *Router) Enrich(banner string, port uint16, proto string) *MatchResult {
	if banner == "" {
		return nil
	}

	var result *MatchResult

	// Phase 1: Recog matching (richer metadata, higher confidence)
	if r.recogDBs != nil {
		result = r.matchRecog(banner, port)
	}

	// Phase 2: Nuclei matching
	nucleiResult := r.matchNuclei(banner, port)
	if nucleiResult != nil {
		if result == nil {
			result = nucleiResult
		} else {
			result.Merge(nucleiResult)
		}
	}

	return result
}

func (r *Router) matchRecog(banner string, port uint16) *MatchResult {
	// Port-specific routing first
	switch {
	case port == 22:
		return r.trySSH(banner)

	case port == 21:
		return r.tryFTP(banner)

	case port == 23:
		return r.tryDB("telnet_banners", banner) // filename-based key (no matches attr)

	case port == 25 || port == 465 || port == 587:
		return r.trySMTP(banner)

	case isHTTPPort(port):
		return r.tryHTTP(banner)

	case port == 110:
		return r.tryDB("pop3.banner", banner)

	case port == 143:
		return r.tryDB("imap4.banner", banner)

	case port == 3306:
		return r.tryMySQL(banner)

	case port == 53:
		return r.tryDB("dns.versionbind", banner)
	}

	// Banner sniffing for non-standard ports
	if strings.HasPrefix(banner, "SSH-") {
		return r.trySSH(banner)
	}
	if strings.HasPrefix(banner, "HTTP/") || strings.HasPrefix(banner, "http/") {
		return r.tryHTTP(banner)
	}

	// Fallback: try all recog DBs, pick highest-preference match
	return r.tryAllDBs(banner)
}

func (r *Router) trySSH(banner string) *MatchResult {
	db := r.recogDBs["ssh.banner"]
	if db == nil {
		return nil
	}

	// Extract SSH software string: after "SSH-x.x-" up to \r\n
	input := banner
	if idx := strings.Index(banner, "\r\n"); idx >= 0 {
		input = banner[:idx]
	} else if idx := strings.Index(banner, "\n"); idx >= 0 {
		input = banner[:idx]
	}

	// Strip SSH protocol prefix: "SSH-2.0-OpenSSH_8.9p1" → "OpenSSH_8.9p1"
	if parts := strings.SplitN(input, "-", 3); len(parts) == 3 && parts[0] == "SSH" {
		input = parts[2]
	}

	return db.Match(input)
}

func (r *Router) tryFTP(banner string) *MatchResult {
	db := r.recogDBs["ftp.banner"]
	if db == nil {
		return nil
	}

	// Extract after status code: "220 vsFTPd 3.0.3" → "vsFTPd 3.0.3"
	input := firstLine(banner)
	if len(input) > 4 && input[3] == ' ' && input[0] >= '0' && input[0] <= '9' {
		input = input[4:]
	}

	return db.Match(input)
}

func (r *Router) trySMTP(banner string) *MatchResult {
	input := firstLine(banner)

	// Try smtp.banner
	if db := r.recogDBs["smtp.banner"]; db != nil {
		if m := db.Match(input); m != nil {
			return m
		}
	}

	return nil
}

func (r *Router) tryHTTP(banner string) *MatchResult {
	var best *MatchResult

	// Try Server header
	if db := r.recogDBs["http_header.server"]; db != nil {
		if m := httpServerRe.FindStringSubmatch(banner); m != nil {
			serverVal := strings.TrimSpace(m[1])
			if res := db.Match(serverVal); res != nil {
				best = res
			}
		}
	}

	// Try X-Powered-By
	if db := r.recogDBs["http_header.x-powered-by"]; db != nil {
		if m := httpXPoweredByRe.FindStringSubmatch(banner); m != nil {
			xpVal := strings.TrimSpace(m[1])
			if res := db.Match(xpVal); res != nil {
				if best == nil {
					best = res
				} else {
					best.Merge(res)
				}
			}
		}
	}

	// Try HTML title
	if db := r.recogDBs["html_title"]; db != nil {
		if m := htmlTitleRe.FindStringSubmatch(banner); m != nil {
			if res := db.Match(m[1]); res != nil {
				if best == nil {
					best = res
				} else {
					best.Merge(res)
				}
			}
		}
	}

	return best
}

func (r *Router) tryMySQL(banner string) *MatchResult {
	db := r.recogDBs["mysql.banners"]
	if db == nil {
		return nil
	}

	// Extract version from MySQL greeting packet
	input := banner
	if m := mysqlVersionRe.FindStringSubmatch(banner); m != nil {
		input = m[1]
	}

	return db.Match(input)
}

func (r *Router) tryDB(name, input string) *MatchResult {
	db := r.recogDBs[name]
	if db == nil {
		return nil
	}
	return db.Match(input)
}

func (r *Router) tryAllDBs(banner string) *MatchResult {
	var best *MatchResult

	for _, db := range r.recogDBs {
		m := db.Match(banner)
		if m == nil {
			continue
		}
		if best == nil || m.Confidence > best.Confidence {
			best = m
		}
	}

	return best
}

func (r *Router) matchNuclei(banner string, port uint16) *MatchResult {
	var result *MatchResult

	// Precompute lowercase banner ONCE for quick-reject across all templates.
	bannerLower := strings.ToLower(banner)

	merge := func(m *MatchResult) {
		if m == nil {
			return
		}
		if result == nil {
			result = m
		} else {
			result.Merge(m)
		}
	}

	// Check port-indexed templates (both TCP and HTTP that declared a port)
	if templates, ok := r.portIndex[port]; ok {
		for _, t := range templates {
			merge(t.MatchWithLower(banner, bannerLower, port))
		}
	}

	// Protocol-specific: only run HTTP templates against HTTP banners
	httpBanner := isHTTPBanner(banner)

	if httpBanner {
		for _, t := range r.nucleiHTTPNoPort {
			merge(t.MatchWithLower(banner, bannerLower, port))
		}
	}

	// TCP templates without port constraints run against all banners
	for _, t := range r.nucleiTCPNoPort {
		merge(t.MatchWithLower(banner, bannerLower, port))
	}

	return result
}

func isHTTPPort(port uint16) bool {
	switch port {
	case 80, 443, 8080, 8443, 8888:
		return true
	}
	return false
}

func isHTTPBanner(banner string) bool {
	return strings.HasPrefix(banner, "HTTP/") || strings.HasPrefix(banner, "http/")
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		line := s[:idx]
		return strings.TrimRight(line, "\r")
	}
	return s
}
