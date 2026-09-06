// Package securehttp creates the Agent's verified package-download client.
package securehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Get downloads only from an HTTPS endpoint whose server certificate chains to
// the platform CA received during enrollment.
func Get(ctx context.Context, workDir, rawURL string, timeout time.Duration) (*http.Response, error) {
	if _, err := ValidateURL(rawURL); err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(workDir, "certs", "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read platform CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("platform CA file contains no certificate")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}},
		CheckRedirect: func(next *http.Request, _ []*http.Request) error {
			_, err := ValidateURL(next.URL.String())
			return err
		},
	}
	return client.Do(req)
}

// ValidateURL rejects cleartext and non-HTTP schemes before any network I/O.
func ValidateURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("download URL must be an absolute HTTPS URL")
	}
	return u, nil
}
