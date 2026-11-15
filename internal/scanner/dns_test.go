package scanner

import (
	"net"
	"testing"
)

func TestEvaluateDNSRecords(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		rootTXT     []string
		dmarcTXT    []string
		expectSPF   bool
		expectDMARC bool
	}{
		{
			name:        "Both SPF and DMARC present",
			domain:      "example.com",
			rootTXT:     []string{"v=spf1 include:_spf.example.com -all"},
			dmarcTXT:    []string{"v=DMARC1; p=reject;"},
			expectSPF:   true,
			expectDMARC: true,
		},
		{
			name:        "Missing both",
			domain:      "example.com",
			rootTXT:     []string{"some other txt"},
			dmarcTXT:    nil,
			expectSPF:   false,
			expectDMARC: false,
		},
		{
			name:        "Case-insensitive matching",
			domain:      "example.com",
			rootTXT:     []string{"V=SPF1 -all"},
			dmarcTXT:    []string{"v=dmarc1; p=none;"},
			expectSPF:   true,
			expectDMARC: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := EvaluateDNSRecords(tt.domain, tt.rootTXT, tt.dmarcTXT)
			if res.HasSPF != tt.expectSPF {
				t.Errorf("expected HasSPF=%v, got %v", tt.expectSPF, res.HasSPF)
			}
			if res.HasDMARC != tt.expectDMARC {
				t.Errorf("expected HasDMARC=%v, got %v", tt.expectDMARC, res.HasDMARC)
			}
		})
	}
}

func TestAuditDNS(t *testing.T) {
	// Skip live network DNS test if environment cannot resolve external DNS
	if _, err := net.LookupTXT("github.com"); err != nil {
		t.Skipf("Skipping live DNS test in restricted/offline environment: %v", err)
	}

	res, err := AuditDNS("https://github.com")
	if err != nil {
		t.Fatalf("AuditDNS returned unexpected error: %v", err)
	}
	if res.Domain != "github.com" {
		t.Errorf("expected domain github.com, got %s", res.Domain)
	}
	if !res.HasSPF || !res.HasDMARC {
		t.Errorf("expected github.com to have both SPF and DMARC records, got: %+v", res)
	}
}