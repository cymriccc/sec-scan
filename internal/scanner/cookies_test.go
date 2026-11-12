package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInspectResponseCookies(t *testing.T) {
	tests := []struct {
		name          string
		setCookie     string
		expectedCount int
	}{
		{
			name:          "Hardened cookie",
			setCookie:     "session_id=xyz123; Path=/; Secure; HttpOnly; SameSite=Strict",
			expectedCount: 0,
		},
		{
			name:          "Missing all flags",
			setCookie:     "session_id=xyz123; Path=/",
			expectedCount: 3,
		},
		{
			name:          "SameSite=None without Secure",
			setCookie:     "tracking=abc; HttpOnly; SameSite=None",
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{
					"Set-Cookie": []string{tt.setCookie},
				},
			}
			findings := InspectResponseCookies(resp)
			if len(findings) != tt.expectedCount {
				t.Errorf("expected %d findings, got %d: %+v", tt.expectedCount, len(findings), findings)
			}
		})
	}
}

func TestAuditCookies(t *testing.T) {
	tests := []struct {
		name          string
		setCookie     string
		expectedCount int
	}{
		{
			name:          "Hardened cookie",
			setCookie:     "session_id=xyz123; Path=/; Secure; HttpOnly; SameSite=Strict",
			expectedCount: 0,
		},
		{
			name:          "Missing all flags",
			setCookie:     "session_id=xyz123; Path=/",
			expectedCount: 3,
		},
		{
			name:          "SameSite=None without Secure",
			setCookie:     "tracking=abc; HttpOnly; SameSite=None",
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Set-Cookie", tt.setCookie)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			findings, err := AuditCookies(srv.URL, "sec-scan-test/1.0", 5*time.Second)
			if err != nil {
				if strings.Contains(err.Error(), "connectex") || strings.Contains(err.Error(), "access permissions") {
					t.Skipf("Skipping live network socket test in sandbox environment: %v", err)
				}
				t.Fatalf("AuditCookies returned error: %v", err)
			}
			if len(findings) != tt.expectedCount {
				t.Errorf("expected %d findings, got %d: %+v", tt.expectedCount, len(findings), findings)
			}
		})
	}
}