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

// EvaluateDNSRecords evaluates TXT records for SPF and DMARC configurations.
func EvaluateDNSRecords(domain string, rootTXT []string, dmarcTXT []string) *DNSCheckResult {
	res := &DNSCheckResult{Domain: domain}

	for _, txt := range rootTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			res.HasSPF = true
			res.SPFRecord = txt
			break
		}
	}

	for _, txt := range dmarcTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			res.HasDMARC = true
			res.DMARCRecord = txt
			break
		}
	}

	return res
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

	// 1. Check SPF record on root domain
	txtRecords, _ := net.LookupTXT(host)

	// 2. Check DMARC record on _dmarc.<domain>
	dmarcRecords, _ := net.LookupTXT("_dmarc." + host)

	return EvaluateDNSRecords(host, txtRecords, dmarcRecords), nil
}