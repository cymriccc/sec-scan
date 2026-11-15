package scanner

import "testing"

func TestAuditDNS(t *testing.T) {
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