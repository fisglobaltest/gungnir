package utils

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"    // ADDED
	"time"

	"github.com/g0ldencybersec/gungnir/pkg/types"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/uuid"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

// ADDED: Rate limiting configuration
var logDelays = map[string]time.Duration{
	"ct.sectigo.com":     15 * time.Second,  // Very slow - frequent 504 errors
	"ct.trustasia.com":   30 * time.Second,  // Extremely slow - 400 errors
	"ct.googleapis.com":  2 * time.Second,   // Moderate - complex rate limiting
	"ct.cloudflare.com":  1 * time.Second,   // Fast - generous limits
	"ct.letsencrypt.org": 1 * time.Second,   // Fast - reliable
	"ct.digicert.com":    1 * time.Second,   // Fast - documented limits
}

var lastRequest = sync.Map{} // ADDED: Track when we last hit each log

var getByScheme = map[string]func(*url.URL) ([]byte, error){
	"http":  readHTTP,
	"https": readHTTP,
	"file": func(u *url.URL) ([]byte, error) {
		return os.ReadFile(u.Path)
	},
}

// readHTTP fetches and reads data from an HTTP-based URL.
func readHTTP(u *url.URL) ([]byte, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func readURL(u *url.URL) ([]byte, error) {
	s := u.Scheme
	queryFn, ok := getByScheme[s]
	if !ok {
		return nil, fmt.Errorf("failed to identify suitable scheme for the URL %q", u.String())
	}
	return queryFn(u)
}

// createLogClient creates a CT log client from a public key and URL.
// MODIFIED: Increased timeout and improved error handling
func createLogClient(key []byte, url string) (*client.LogClient, error) {
	pemPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	})
	opts := jsonclient.Options{PublicKey: string(pemPK), UserAgent: "gungnir-" + uuid.New().String()}
	
	// ENHANCED: Better transport configuration with longer timeouts
	transport := &http.Transport{
		// CRITICAL FIX: Disable HTTP/2 to prevent context cancellation deadlock
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		
		// INCREASED timeouts for better reliability
		TLSHandshakeTimeout:   45 * time.Second,  // Increased from 30s
		ResponseHeaderTimeout: 60 * time.Second,  // Increased from 30s
		MaxIdleConnsPerHost:   3,                 // Reduced from 10 to be gentler
		DisableKeepAlives:     false,             // Enable keep-alives for efficiency
		MaxIdleConns:          20,                // Reduced from 100
		IdleConnTimeout:       60 * time.Second,  // Reduced from 90s
		ExpectContinueTimeout: 2 * time.Second,   // Increased from 1s
	}
	
	httpClient := &http.Client{
		Timeout:   90 * time.Second,  // CRITICAL: Increased from 27s to 90s
		Transport: transport,
	}
	
	c, err := client.New(url, httpClient, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON client: %v", err)
	}
	return c, nil
}

func PopulateLogs(logListURL string) ([]types.CtLog, error) {
	u, err := url.Parse(logListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	body, err := readURL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to get log list data: %v", err)
	}
	// Get data for all usable logs.
	logList, err := loglist3.NewFromJSON(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	usable := logList.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus, loglist3.PendingLogStatus, loglist3.ReadOnlyLogStatus, loglist3.QualifiedLogStatus, loglist3.RetiredLogStatus})
	var logs []types.CtLog
	for _, operator := range usable.Operators {
		for _, log := range operator.Logs {
			logID := base64.StdEncoding.EncodeToString(log.LogID)
			c, err := createLogClient(log.Key, log.URL)
			if err != nil {
				return nil, fmt.Errorf("failed to create log client: %v", err)
			}
			l := types.CtLog{
				Id:     logID,
				Name:   log.Description,
				Client: c,
			}
			logs = append(logs, l)
		}
	}
	return logs, nil
}

// Checks if a domain is a subdomain of any root domain in the global map
func IsSubdomain(domain string, rootDomains map[string]bool) bool {
	if _, ok := rootDomains[domain]; ok {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := range parts {
		parentDomain := strings.Join(parts[i:], ".")
		if _, ok := rootDomains[parentDomain]; ok {
			return true
		}
	}

	return false
}

func JsonOutput(cert *x509.Certificate) {
	certInfo := types.CertificateInfo{
		OriginIP:         "",
		Organization:     cert.Subject.Organization,
		OrganizationUnit: cert.Subject.OrganizationalUnit,
		CommonName:       cert.Subject.CommonName,
		SAN:              cert.DNSNames,
		Domains:          append([]string{cert.Subject.CommonName}, cert.DNSNames...),
		Emails:           cert.EmailAddresses,
		IPAddrs:          cert.IPAddresses,
	}
	outputJson, _ := json.Marshal(certInfo)
	fmt.Println(string(outputJson))
}

// ADDED: Rate limiting function to wait before hitting CT logs
func WaitForLog(logURL string) {
	// Figure out which provider this is and get appropriate delay
	var delay time.Duration = 2 * time.Second // default delay
	
	for provider, providerDelay := range logDelays {
		if strings.Contains(logURL, provider) {
			delay = providerDelay
			break
		}
	}
	
	// Check when we last hit this provider
	if lastTime, exists := lastRequest.Load(logURL); exists {
		timeSince := time.Since(lastTime.(time.Time))
		if timeSince < delay {
			waitTime := delay - timeSince
			fmt.Printf("[RATE LIMIT] Waiting %v before hitting %s\n", waitTime, extractHostname(logURL))
			time.Sleep(waitTime)
		}
	}
	
	// Record this request time
	lastRequest.Store(logURL, time.Now())
}

// ADDED: Helper function to extract hostname for cleaner logging
func extractHostname(url string) string {
	if strings.Contains(url, "://") {
		parts := strings.Split(url, "://")
		if len(parts) > 1 {
			hostPart := strings.Split(parts[1], "/")[0]
			return hostPart
		}
	}
	return url
}

// ADDED: Function to check if we should retry an error
func ShouldRetryError(err error) bool {
	if err == nil {
		return false
	}
	
	errStr := strings.ToLower(err.Error())
	
	// Retryable errors
	retryableErrors := []string{
		"504",                    // Gateway Timeout (Sectigo)
		"502",                    // Bad Gateway
		"503",                    // Service Unavailable
		"429",                    // Too Many Requests
		"500",                    // Internal Server Error
		"timeout",                // Any timeout
		"context deadline exceeded",
		"connection refused",
		"connection reset",
		"network is unreachable",
	}
	
	for _, retryableErr := range retryableErrors {
		if strings.Contains(errStr, retryableErr) {
			return true
		}
	}
	
	// TrustAsia returns 400 for rate limiting (non-standard)
	if strings.Contains(errStr, "400") && strings.Contains(errStr, "trustasia") {
		return true
	}
	
	return false
}
