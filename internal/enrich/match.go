package enrich

// MatchResult holds enrichment fields from any source.
type MatchResult struct {
	Source         string // "recog:http_header.server", "nuclei:nginx-version-detect"
	ServiceVendor  string
	ServiceProduct string
	ServiceVersion string
	ServiceCPE     string // cpe:2.3 or cpe:/ format
	OSVendor       string
	OSProduct      string
	OSVersion      string
	OSFamily       string
	OSDevice       string
	HWVendor       string
	HWProduct      string
	Description    string
	Confidence     float64 // recog preference (0.0–1.0), nuclei gets 0.5
	NucleiIDs      []string
	Extra          map[string]string // overflow fields
}

// Merge fills empty fields from other result. Higher confidence wins for conflicts.
func (m *MatchResult) Merge(other *MatchResult) {
	if other == nil {
		return
	}
	if m.ServiceVendor == "" {
		m.ServiceVendor = other.ServiceVendor
	}
	if m.ServiceProduct == "" {
		m.ServiceProduct = other.ServiceProduct
	}
	if m.ServiceVersion == "" {
		m.ServiceVersion = other.ServiceVersion
	}
	if m.ServiceCPE == "" {
		m.ServiceCPE = other.ServiceCPE
	}
	if m.OSVendor == "" {
		m.OSVendor = other.OSVendor
	}
	if m.OSProduct == "" {
		m.OSProduct = other.OSProduct
	}
	if m.OSVersion == "" {
		m.OSVersion = other.OSVersion
	}
	if m.OSFamily == "" {
		m.OSFamily = other.OSFamily
	}
	if m.OSDevice == "" {
		m.OSDevice = other.OSDevice
	}
	if m.HWVendor == "" {
		m.HWVendor = other.HWVendor
	}
	if m.HWProduct == "" {
		m.HWProduct = other.HWProduct
	}
	if m.Description == "" {
		m.Description = other.Description
	}
	if m.Source == "" {
		m.Source = other.Source
	}
	if other.Confidence > m.Confidence {
		// Higher confidence: overwrite non-empty fields
		if other.ServiceVendor != "" {
			m.ServiceVendor = other.ServiceVendor
		}
		if other.ServiceProduct != "" {
			m.ServiceProduct = other.ServiceProduct
		}
		if other.ServiceVersion != "" {
			m.ServiceVersion = other.ServiceVersion
		}
		if other.ServiceCPE != "" {
			m.ServiceCPE = other.ServiceCPE
		}
		m.Confidence = other.Confidence
		m.Source = other.Source
	}
	m.NucleiIDs = append(m.NucleiIDs, other.NucleiIDs...)

	// Merge extra fields
	if len(other.Extra) > 0 {
		if m.Extra == nil {
			m.Extra = make(map[string]string, len(other.Extra))
		}
		for k, v := range other.Extra {
			if _, ok := m.Extra[k]; !ok {
				m.Extra[k] = v
			}
		}
	}
}
