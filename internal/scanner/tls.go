package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"
)

type TLSCheckResult struct {
	Issuer         string
	CommonName     string
	ExpiryDate     time.Time
	DaysRemaining int
	TLSVersion     string
	DNSNames       []string
	IsExpired      bool
	ExpiresSoon    bool // Warning if expiring in < 30 days
}

func AuditTLS(targetURL string) (*TLSCheckResult, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	host := parsed.Hostname()
	if host == "" {
		host = targetURL
	}

	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	address := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no TLS certificates found")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	var tlsVer string
	switch state.Version {
	case tls.VersionTLS13:
		tlsVer = "TLS 1.3"
	case tls.VersionTLS12:
		tlsVer = "TLS 1.2"
	case tls.VersionTLS11:
		tlsVer = "TLS 1.1 (Deprecated)"
	case tls.VersionTLS10:
		tlsVer = "TLS 1.0 (Deprecated)"
	default:
		tlsVer = "Unknown"
	}

	return &TLSCheckResult{
		Issuer:         cert.Issuer.CommonName,
		CommonName:     cert.Subject.CommonName,
		ExpiryDate:     cert.NotAfter,
		DaysRemaining: daysRemaining,
		TLSVersion:     tlsVer,
		DNSNames:       cert.DNSNames,
		IsExpired:      now.After(cert.NotAfter),
		ExpiresSoon:    daysRemaining <= 30,
	}, nil
}