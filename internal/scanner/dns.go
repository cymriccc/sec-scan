package scanner

import (
	"net"
	"net/url"
	"strings"
)

type DNSCheckResult struct {
	Domain      string `json:"domain"`
	HasSPF      bool   `json:"has_spf"`
	SPFRecord   string `json:"spf_record,omitempty"`
	HasDMARC    bool   `json:"has_dmarc"`
	DMARCRecord string `json:"dmarc_record,omitempty"`
}

// AuditDNS checks the target domain for SPF and DMARC TXT records.
func AuditDNS(targetURL string) (*DNSCheckResult, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	host := parsed.Hostname()
	if host == "" {
		host = targetURL
	}

	res := &DNSCheckResult{Domain: host}

	// 1. Check SPF record on root domain
	txtRecords, err := net.LookupTXT(host)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
				res.HasSPF = true
				res.SPFRecord = txt
				break
			}
		}
	}

	// 2. Check DMARC record on _dmarc.<domain>
	dmarcRecords, err := net.LookupTXT("_dmarc." + host)
	if err == nil {
		for _, txt := range dmarcRecords {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
				res.HasDMARC = true
				res.DMARCRecord = txt
				break
			}
		}
	}

	return res, nil
}