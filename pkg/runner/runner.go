package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"github.com/anthdm/hollywood/actor"
	"github.com/fisglobaltest/gungnir/pkg/utils"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/nats-io/nats.go"

	"github.com/fsnotify/fsnotify"
	"github.com/fisglobaltest/gungnir/pkg/types"
)

// Global variables
var (
	logListUrl          = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
	defaultRateLimitMap = map[string]time.Duration{
	    "Google":        2 * time.Second,
	    "Sectigo":       15 * time.Second,
	    "Let's Encrypt": time.Second,
	    "DigiCert":      time.Second,
	    "TrustAsia":     30 * time.Second,
	    "Cloudflare":    time.Second,
	    "Argon":         3 * time.Second,     // Add Google Argon logs
	    "Xenon":         3 * time.Second,     // Add Google Xenon logs  
	    "Nimbus":        time.Second,         // Cloudflare Nimbus
	    "Mammoth":       15 * time.Second,    // Sectigo Mammoth
	    "Sabre":         15 * time.Second,    // Sectigo Sabre
	}
)

type Runner struct {
	options     *Options
	logClients  []types.CtLog
	rootDomains map[string]bool
	// followFile     map[string]bool
	rateLimitMap   map[string]time.Duration
	entryTasksChan chan types.EntryTask
	watcher        *fsnotify.Watcher
	restartChan    chan struct{}
	outputMutex    sync.Mutex
	natsPub        bool
	natsConn       *nats.Conn
	actorPID       *actor.PID
	useActor       bool
	actorEngine    *actor.Engine
	backoffTracker map[string]time.Time
	backoffMutex   sync.RWMutex
}

func (r *Runner) loadRootDomains() error {
	if r.options.RootList == "" {
		return nil
	}

	file, err := os.Open(r.options.RootList)
	if err != nil {
		return fmt.Errorf("failed to open root domains file: %v", err)
	}
	defer file.Close()

	r.rootDomains = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		r.rootDomains[scanner.Text()] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading root domains file: %v", err)
	}

	return nil
}

func (r *Runner) setupFileWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	r.watcher = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					if err := r.loadRootDomains(); err != nil {
						log.Printf("Error reloading domains: %v", err)
						continue
					}
					r.restartChan <- struct{}{}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v", err)
			}
		}
	}()

	return watcher.Add(r.options.RootList)
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options:     options,
		rootDomains: make(map[string]bool),
		restartChan: make(chan struct{}),
		backoffTracker: make(map[string]time.Time),
	}

	if err := runner.loadRootDomains(); err != nil {
		return nil, fmt.Errorf("failed to load root domains: %v", err)
	}

	// Verify that we have root domains if output directory is specified
	if runner.options.OutputDir != "" && len(runner.rootDomains) == 0 {
		return nil, fmt.Errorf("output directory specified but no root domains loaded")
	}

	if runner.options.WatchFile {
		if err := runner.setupFileWatcher(); err != nil {
			return nil, fmt.Errorf("failed to setup file watcher: %v", err)
		}
	}

	var err error
	runner.logClients, err = utils.PopulateLogs(logListUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to populate logs: %v", err)
	}

	// NATS setup if needed
	if runner.options.NatsSubject != "" && runner.options.NatsUrl != "" && runner.options.NatsCredFile != "" {
		nc, err := nats.Connect(runner.options.NatsUrl, nats.UserCredentials(runner.options.NatsCredFile))
		if err != nil {
			return nil, fmt.Errorf("failed to make nats connectoin: %v", err)
		}

		runner.natsConn = nc
		runner.natsPub = true
	} else {
		runner.natsConn = nil
		runner.natsPub = false
	}

	if runner.options.ActorPID != nil {
		runner.useActor = true
		runner.actorPID = runner.options.ActorPID

		if runner.options.ActorEngine != nil {
			runner.actorEngine = runner.options.ActorEngine
		} else {
			log.Println("No actor engine provided, creating a new one")
			// Fall back to creating a new engine if none is provided
			runner.actorEngine, err = actor.NewEngine(actor.EngineConfig{})
			if err != nil {
				return nil, fmt.Errorf("failed to create actor engine: %v", err)
			}
		}
	}

	runner.entryTasksChan = make(chan types.EntryTask, len(runner.logClients)*100)
	runner.rateLimitMap = defaultRateLimitMap

	return runner, nil
}


// Add this function to help identify which provider we're dealing with
func getProviderName(logURL string) string {
	logURL = strings.ToLower(logURL)
	switch {
	case strings.Contains(logURL, "googleapis"):
		return "Google"
	case strings.Contains(logURL, "sectigo"):
		return "Sectigo"  
	case strings.Contains(logURL, "trustasia"):
		return "TrustAsia"
	case strings.Contains(logURL, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(logURL, "letsencrypt"):
		return "Let's Encrypt"
	case strings.Contains(logURL, "digicert"):
		return "DigiCert"
	default:
		return "Unknown"
	}
}


func (r *Runner) Run() {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-signals:
				fmt.Fprintf(os.Stderr, "Shutdown signal received\n")
				cancel()
				return
			case <-r.restartChan:
				fmt.Fprintf(os.Stderr, "Restarting scan due to file update\n")
				cancel()
				ctx, cancel = context.WithCancel(context.Background())
				go r.startScan(ctx, &wg)
			}
		}
	}()

	r.startScan(ctx, &wg)

	wg.Wait()
	close(r.entryTasksChan)
	if r.watcher != nil {
		r.watcher.Close()
	}
	if r.natsConn != nil {
		r.natsConn.Close()
	}	
	fmt.Fprintf(os.Stderr, "Gracefully shutdown all routines\n")
}

func (r *Runner) startScan(ctx context.Context, wg *sync.WaitGroup) {
	// Start entry workers
	for i := 0; i < len(r.logClients); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.entryWorker(ctx)
		}()
	}

	// Start scanning logs
	for _, ctl := range r.logClients {
		wg.Add(1)
		go r.scanLog(ctx, ctl, wg)
	}
}

func (r *Runner) entryWorker(ctx context.Context) {
	for {
		select {
		case task, ok := <-r.entryTasksChan:
			if !ok {
				return // Channel closed, terminate the goroutine
			}
			r.processEntries(task.Entries, task.Index)
		case <-ctx.Done():
			return // Context cancelled, terminate the goroutine
		}
	}
}

func (r *Runner) scanLog(ctx context.Context, ctl types.CtLog, wg *sync.WaitGroup) {
	defer wg.Done()
	// Identify the provider for better logging
	providerName := getProviderName(ctl.Client.BaseURI())
	if r.options.Verbose {
		fmt.Fprintf(os.Stderr, "Starting scan for %s (%s)\n", ctl.Name, providerName)
	}
	// Determine ticker duration based on log name or URL
	tickerDuration := time.Second // Default duration
	logNameLower := strings.ToLower(ctl.Name)
	logURL := strings.ToLower(ctl.Client.BaseURI())

	// Check both name and URL for matches
	for key, duration := range r.rateLimitMap {
		keyLower := strings.ToLower(key)
		if strings.Contains(logNameLower, keyLower) || strings.Contains(logURL, keyLower) {
			tickerDuration = duration
			break
		}
	}

	// Special handling for specific problematic logs
	if strings.Contains(logURL, "429") || strings.Contains(logNameLower, "sabre") {
		tickerDuration = 20 * time.Second // Even slower for heavily rate-limited logs
	}

	// Is this a google log?
	IsGoogleLog := strings.Contains(ctl.Name, "Google")
	// Determine batch size based on provider
	batchSize := int64(256) // Default
	if strings.Contains(ctl.Name, "Sectigo") {
		batchSize = 50
	} else if strings.Contains(ctl.Name, "TrustAsia") {
		batchSize = 20
	} else if strings.Contains(ctl.Name, "Google") {
		batchSize = 31
	}

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	var start, end int64
	var err error

	// Retry fetching the initial STH with context-aware back-off
	for retries := 0; retries < 3; retries++ {
		if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
			if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Failed to update STH for %s: %v\n", ctl.Name, err)
			}
			
			// Determine wait time based on error type and provider
			waitTime := 30 * time.Second
			errStr := strings.ToLower(err.Error())
			
			// Special handling for known error patterns
			if strings.Contains(errStr, "504") || strings.Contains(errStr, "timeout") {
				waitTime = 60 * time.Second
				if strings.Contains(ctl.Name, "Sectigo") {
					waitTime = 120 * time.Second
				}
			} else if strings.Contains(errStr, "429") || 
					(strings.Contains(errStr, "400") && strings.Contains(ctl.Name, "TrustAsia")) {
				// Rate limiting - use exponential backoff
				waitTime = tickerDuration * 2
				if waitTime > 5*time.Minute {
					waitTime = 5*time.Minute
				}
			}
			
			if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Waiting %v before retrying %s\n", waitTime, ctl.Name)
			}
			
			select {
			case <-ctx.Done():
				return
			case <-time.After(waitTime):
			}
			continue
		}
		break
	}

	// Initialize start position more carefully
	if end > 1000 {
		start = end - 1000  // Start 1000 entries back for active logs
	} else if end > 20 {
		start = end - 20    // Start 20 entries back for smaller logs
	} else {
		start = 0          // Start from beginning for very small logs
	}

	if r.options.Verbose {
		fmt.Fprintf(os.Stderr, "[INIT] %s: Starting scan from %d to %d\n", ctl.Name, start, end)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if start >= end {				
				if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "Failed to update STH for %s: %v\n", ctl.Name, err)
					}
					
					// Determine wait time based on error type and provider
					waitTime := 60 * time.Second // Default longer wait for STH errors
					errStr := strings.ToLower(err.Error())
					
					// Special handling for known error patterns
					if strings.Contains(errStr, "504") || strings.Contains(errStr, "timeout") {
						waitTime = 120 * time.Second
						if strings.Contains(ctl.Name, "Sectigo") {
							waitTime = 180 * time.Second // 3 minutes for Sectigo
						}
					} else if strings.Contains(errStr, "429") {
						// For 429 on STH, back off significantly
						waitTime = 5 * time.Minute
						if r.options.Verbose {
							fmt.Fprintf(os.Stderr, "Rate limited on STH for %s, backing off for 5 minutes\n", ctl.Name)
						}
					} else if strings.Contains(errStr, "500") {
						// Server error - wait longer
						waitTime = 2 * time.Minute
					}
					
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "Waiting %v before retrying STH for %s\n", waitTime, ctl.Name)
					}
					
					select {
					case <-ctx.Done():
						return
					case <-time.After(waitTime):
					}
					continue
				}
			}	

			// Work with google logs
			if IsGoogleLog {
				for start < end {
					batchEnd := start + batchSize
					if batchEnd > end {
						batchEnd = end
					}
					
					// Log the request details
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "[DEBUG] %s: Requesting entries [%d:%d] (batch size: %d)\n", 
							ctl.Name, start, batchEnd-1, batchEnd-start)
					}
					
					entries, err := RetryGetEntries(ctx, ctl.Client, start, batchEnd-1, 3)
					if err != nil {
						// Enhanced error logging
						fmt.Fprintf(os.Stderr, "Error fetching entries for %s (%s): %v\n", ctl.Name, providerName, err)
						fmt.Fprintf(os.Stderr, "[ERROR DETAILS] Log: %s, URL: %s, Range: [%d:%d], Batch Size: %d\n", 
							ctl.Name, ctl.Client.BaseURI(), start, batchEnd-1, batchEnd-start)
						
						// Determine wait time based on error type and provider
						waitTime := 30 * time.Second
						errStr := strings.ToLower(err.Error())
						
						// Check for specific error types
						if strings.Contains(errStr, "400") {
							fmt.Fprintf(os.Stderr, "[400 ERROR] This usually means invalid parameters. Current end: %d, start: %d, batchEnd: %d\n", 
								end, start, batchEnd)
						}
						
						// Special handling for known error patterns
						if strings.Contains(errStr, "504") || strings.Contains(errStr, "timeout") {
							waitTime = 60 * time.Second
							if strings.Contains(ctl.Name, "Sectigo") {
								waitTime = 120 * time.Second
							}
						} else if strings.Contains(errStr, "429") || 
								(strings.Contains(errStr, "400") && strings.Contains(ctl.Name, "TrustAsia")) {
							// Rate limiting - use exponential backoff
							waitTime = tickerDuration * 2
							if waitTime > 5*time.Minute {
								waitTime = 5*time.Minute
							}
						}
						
						// Backoff tracker
						r.backoffMutex.Lock()
						lastError, exists := r.backoffTracker[ctl.Name]
						if exists && time.Since(lastError) < 5*time.Minute {
							// Recently had an error, double the wait time
							waitTime = waitTime * 2
							if r.options.Verbose {
								fmt.Fprintf(os.Stderr, "Recent errors detected for %s, doubling wait time to %v\n", ctl.Name, waitTime)
							}
						}
						r.backoffTracker[ctl.Name] = time.Now()
						r.backoffMutex.Unlock()
						
						if r.options.Verbose {
							fmt.Fprintf(os.Stderr, "Waiting %v before retrying %s\n", waitTime, ctl.Name)
						}
						
						select {
						case <-ctx.Done():
							return
						case <-time.After(waitTime):
						}
						break // Break the inner loop on error
					}

					if len(entries.Entries) > 0 {
						if r.options.Verbose {
							fmt.Fprintf(os.Stderr, "[SUCCESS] %s: Got %d entries\n", ctl.Name, len(entries.Entries))
						}
						r.entryTasksChan <- types.EntryTask{
							Entries: entries,
							Index:   start,
						}
						start += int64(len(entries.Entries))
					} else {
						if r.options.Verbose {
							fmt.Fprintf(os.Stderr, "[INFO] %s: No entries returned for range [%d:%d]\n", 
								ctl.Name, start, batchEnd-1)
						}
						break // No more entries to process, break the loop
					}
				}
				continue // Continue with the outer ticker loop
			} else { // Non Google handler
				batchEnd := start + batchSize
				if batchEnd > end {
					batchEnd = end
				}
				
				// Log the request details
				if r.options.Verbose {
					fmt.Fprintf(os.Stderr, "[DEBUG] %s: Requesting entries [%d:%d] (batch size: %d)\n", 
						ctl.Name, start, batchEnd-1, batchEnd-start)
				}
				
				// Check if the range is valid before making request
				if start >= end {
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "[INFO] %s: Already caught up (start: %d >= end: %d)\n", 
							ctl.Name, start, end)
					}
					continue
				}
				
				entries, err := RetryGetEntries(ctx, ctl.Client, start, batchEnd-1, 3)
				if err != nil {
					// Enhanced error logging
					fmt.Fprintf(os.Stderr, "Error fetching entries for %s (%s): %v\n", ctl.Name, providerName, err)
					fmt.Fprintf(os.Stderr, "[ERROR DETAILS] Log: %s, URL: %s, Range: [%d:%d], Batch Size: %d\n", 
						ctl.Name, ctl.Client.BaseURI(), start, batchEnd-1, batchEnd-start)
					
					// Determine wait time based on error type and provider
					waitTime := 30 * time.Second
					errStr := strings.ToLower(err.Error())
					
					// Check for specific error types
					if strings.Contains(errStr, "400") {
						fmt.Fprintf(os.Stderr, "[400 ERROR] This usually means invalid parameters. Current end: %d, start: %d, batchEnd: %d\n", 
							end, start, batchEnd)
						
						// Try to diagnose the issue
						if start > end {
							fmt.Fprintf(os.Stderr, "[DIAGNOSIS] start > end, this is invalid\n")
						}
						if batchEnd-1 < start {
							fmt.Fprintf(os.Stderr, "[DIAGNOSIS] batchEnd-1 < start, this is invalid\n")
						}
						if batchEnd-start > 1000 {
							fmt.Fprintf(os.Stderr, "[DIAGNOSIS] Batch size might be too large\n")
						}
					}
					
					// Special handling for known error patterns
					if strings.Contains(errStr, "504") || strings.Contains(errStr, "timeout") {
						waitTime = 60 * time.Second
						if strings.Contains(ctl.Name, "Sectigo") {
							waitTime = 120 * time.Second
						}
					} else if strings.Contains(errStr, "429") || 
							(strings.Contains(errStr, "400") && strings.Contains(ctl.Name, "TrustAsia")) {
						// Rate limiting - use exponential backoff
						waitTime = tickerDuration * 2
						if waitTime > 5*time.Minute {
							waitTime = 5*time.Minute
						}
					}
					
					// Backoff tracker
					r.backoffMutex.Lock()
					lastError, exists := r.backoffTracker[ctl.Name]
					if exists && time.Since(lastError) < 5*time.Minute {
						// Recently had an error, double the wait time
						waitTime = waitTime * 2
						if r.options.Verbose {
							fmt.Fprintf(os.Stderr, "Recent errors detected for %s, doubling wait time to %v\n", ctl.Name, waitTime)
						}
					}
					r.backoffTracker[ctl.Name] = time.Now()
					r.backoffMutex.Unlock()
					
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "Waiting %v before retrying %s\n", waitTime, ctl.Name)
					}
					
					select {
					case <-ctx.Done():
						return
					case <-time.After(waitTime):
					}
					continue // Continue the outer ticker loop
				}

				if len(entries.Entries) > 0 {
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "[SUCCESS] %s: Got %d entries\n", ctl.Name, len(entries.Entries))
					}
					r.entryTasksChan <- types.EntryTask{
						Entries: entries,
						Index:   start,
					}
					start += int64(len(entries.Entries))
				} else {
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "[INFO] %s: No entries returned for range [%d:%d]\n", 
							ctl.Name, start, batchEnd-1)
					}
					// Move forward to avoid getting stuck
					start = batchEnd
				}
			}
		}
	}
}
func (r *Runner) fetchAndUpdateSTH(ctx context.Context, ctl types.CtLog, end *int64) error {
	wsth, err := ctl.Client.GetSTH(ctx)
	if err != nil {
		return err
	}
	*end = int64(wsth.TreeSize)
	return nil
}

func (r *Runner) processEntries(results *ct.GetEntriesResponse, start int64) {
	index := start

	for _, entry := range results.Entries {
		index++
		rle, err := ct.RawLogEntryFromLeaf(index, &entry)
		if err != nil {
			if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Failed to get parse entry %d: %v", index, err)
			}
			break
		}

		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			r.logCertInfo(rle)
		case ct.PrecertLogEntryType:
			r.logPrecertInfo(rle)
		default:
			if r.options.Verbose {
				fmt.Fprintln(os.Stderr, "Unknown entry")
			}
		}
	}
}

func (r *Runner) writeToHostFile(hostname string, data interface{}) error {
	// Early return if no output directory specified or if root domains is empty
	if r.options.OutputDir == "" || len(r.rootDomains) == 0 {
		return nil
	}

	// Find matching root domain
	var matchingRoot string
	for root := range r.rootDomains {
		if utils.IsSubdomain(hostname, map[string]bool{root: true}) {
			matchingRoot = root
			break
		}
	}

	// If no matching root domain found, return
	if matchingRoot == "" {
		return nil
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(r.options.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Sanitize root domain for filename
	safeRootDomain := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, matchingRoot)

	filePath := filepath.Join(r.options.OutputDir, safeRootDomain+".txt")

	// Use mutex to prevent concurrent file access
	r.outputMutex.Lock()
	defer r.outputMutex.Unlock()

	// Open file in append mode
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %v", err)
	}
	defer f.Close()

	var output string
	if r.options.JsonOutput {
		jsonData, err := json.Marshal(struct {
			Hostname string      `json:"hostname"`
			Data     interface{} `json:"data"`
		}{
			Hostname: hostname,
			Data:     data,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		output = string(jsonData) + "\n"
	} else {
		// output = fmt.Sprintf("Hostname: %s\nData: %v\n---\n", hostname, data)
		output = fmt.Sprintf("Hostname: %s\n", hostname)
	}

	if _, err := f.WriteString(output); err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

func (r *Runner) logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
		return
	}

	// Only process if we have root domains and output directory
	if r.options.OutputDir != "" && len(r.rootDomains) > 0 {
		// Handle CommonName
		if parsedEntry.X509Cert.Subject.CommonName != "" {
			if err := r.writeToHostFile(parsedEntry.X509Cert.Subject.CommonName, parsedEntry.X509Cert); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", parsedEntry.X509Cert.Subject.CommonName, err)
				}
			}
		}

		// Handle DNS names
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if err := r.writeToHostFile(domain, parsedEntry.X509Cert); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", domain, err)
				}
			}
		}
	} else if r.useActor {
		if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
			r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: parsedEntry.X509Cert.Subject.CommonName})
		}
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: domain})
			}
		}
	} else if r.natsPub {
		if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
			err := r.natsConn.Publish(r.options.NatsSubject, []byte(parsedEntry.X509Cert.Subject.CommonName))
			if err != nil {
				log.Printf("Error writing to NATs: %v", err)
			}
		}
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				err := r.natsConn.Publish(r.options.NatsSubject, []byte(domain))
				if err != nil {
					log.Printf("Error writing to NATs: %v", err)
				}
			}
		}
	} else {
		// Original stdout output behavior
		if len(r.rootDomains) == 0 {
			if r.options.JsonOutput {
				utils.JsonOutput(parsedEntry.X509Cert)
			} else {
				fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
				for _, domain := range parsedEntry.X509Cert.DNSNames {
					fmt.Println(domain)
				}
			}
		} else {
			if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
				if r.options.JsonOutput {
					utils.JsonOutput(parsedEntry.X509Cert)
				} else {
					fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
				}
			}
			for _, domain := range parsedEntry.X509Cert.DNSNames {
				if utils.IsSubdomain(domain, r.rootDomains) {
					if r.options.JsonOutput {
						utils.JsonOutput(parsedEntry.X509Cert)
					} else {
						fmt.Println(domain)
					}
				}
			}
		}
	}
}

func (r *Runner) logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
		return
	}

	// Only process if we have root domains and output directory
	if r.options.OutputDir != "" && len(r.rootDomains) > 0 {
		// Handle CommonName
		if parsedEntry.Precert.TBSCertificate.Subject.CommonName != "" {
			if err := r.writeToHostFile(parsedEntry.Precert.TBSCertificate.Subject.CommonName, parsedEntry.Precert.TBSCertificate); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", parsedEntry.Precert.TBSCertificate.Subject.CommonName, err)
				}
			}
		}

		// Handle DNS names
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if err := r.writeToHostFile(domain, parsedEntry.Precert.TBSCertificate); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", domain, err)
				}
			}
		}
	} else if r.useActor {
		if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
			r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: parsedEntry.Precert.TBSCertificate.Subject.CommonName})
		}
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: domain})
			}
		}
	} else if r.natsPub {
		if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
			err := r.natsConn.Publish(r.options.NatsSubject, []byte(parsedEntry.Precert.TBSCertificate.Subject.CommonName))
			if err != nil {
				log.Printf("Error writing to NATs: %v", err)
			}
		}
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				err := r.natsConn.Publish(r.options.NatsSubject, []byte(domain))
				if err != nil {
					log.Printf("Error writing to NATs: %v", err)
				}
			}
		}
	} else {
		// Original stdout output behavior
		if len(r.rootDomains) == 0 {
			if r.options.JsonOutput {
				utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
			} else {
				fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
				for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
					fmt.Println(domain)
				}
			}
		} else {
			if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
				if r.options.JsonOutput {
					utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
				} else {
					fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
				}
			}
			for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
				if utils.IsSubdomain(domain, r.rootDomains) {
					if r.options.JsonOutput {
						utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
					} else {
						fmt.Println(domain)
					}
				}
			}
		}
	}
}
