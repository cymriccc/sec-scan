package scanner

import "fmt"

// HeaderRemediation holds copy-paste configuration snippets for missing headers.
type HeaderRemediation struct {
	Header  string
	Nginx   string
	Apache  string
	Vercel  string
}

// GetHeaderRemediation returns actionable server configuration snippets for a missing security header.
func GetHeaderRemediation(header string) HeaderRemediation {
	switch header {
	case "Strict-Transport-Security":
		return HeaderRemediation{
			Header: header,
			Nginx:  `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
			Apache: `Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"`,
			Vercel: `"key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload"`,
		}
	case "X-Frame-Options":
		return HeaderRemediation{
			Header: header,
			Nginx:  `add_header X-Frame-Options "DENY" always;`,
			Apache: `Header always set X-Frame-Options "DENY"`,
			Vercel: `"key": "X-Frame-Options", "value": "DENY"`,
		}
	case "X-Content-Type-Options":
		return HeaderRemediation{
			Header: header,
			Nginx:  `add_header X-Content-Type-Options "nosniff" always;`,
			Apache: `Header always set X-Content-Type-Options "nosniff"`,
			Vercel: `"key": "X-Content-Type-Options", "value": "nosniff"`,
		}
	case "Content-Security-Policy":
		return HeaderRemediation{
			Header: header,
			Nginx:  `add_header Content-Security-Policy "default-src 'self';" always;`,
			Apache: `Header always set Content-Security-Policy "default-src 'self';"`,
			Vercel: `"key": "Content-Security-Policy", "value": "default-src 'self';"`,
		}
	case "Referrer-Policy":
		return HeaderRemediation{
			Header: header,
			Nginx:  `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
			Apache: `Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
			Vercel: `"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"`,
		}
	case "Permissions-Policy":
		return HeaderRemediation{
			Header: header,
			Nginx:  `add_header Permissions-Policy "geolocation=(), microphone=()" always;`,
			Apache: `Header always set Permissions-Policy "geolocation=(), microphone=()"`,
			Vercel: `"key": "Permissions-Policy", "value": "geolocation=(), microphone=()"`,
		}
	default:
		return HeaderRemediation{
			Header: header,
			Nginx:  fmt.Sprintf(`# Missing header: %s`, header),
			Apache: fmt.Sprintf(`# Missing header: %s`, header),
			Vercel: fmt.Sprintf(`// Missing header: %s`, header),
		}
	}
}