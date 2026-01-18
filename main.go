package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gtuk/discordwebhook"
	"github.com/joho/godotenv"
	"github.com/likexian/whois"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

// ErrDomainNotRegistered is returned when a domain is not registered
var ErrDomainNotRegistered = errors.New("domain is not registered")

// ErrRDAPFailed is returned when RDAP query fails and we should try WHOIS
var ErrRDAPFailed = errors.New("RDAP query failed")

// HTTP client with timeout for RDAP requests
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// RDAP bootstrap data
var (
	rdapBootstrap     map[string]string // TLD -> RDAP base URL
	rdapBootstrapLock sync.RWMutex
)

// Configuration
var (
	domainCheckDelay   = 2 * time.Second
	bootstrapCacheTTL  = 12 * time.Hour
	bootstrapURL       = "https://data.iana.org/rdap/dns.json"
	bootstrapCacheFile = "rdap-bootstrap.json"
	bootstrapTSFile    = "rdap-bootstrap.timestamp"
)

// Status file markers
const (
	statusRegistered   = "REGISTERED"
	statusUnregistered = "UNREGISTERED"
)

// Patterns that indicate a domain is not registered/available
var notRegisteredPatterns = []string{
	"no match for",
	"not found",
	"no data found",
	"no entries found",
	"status: free",
	"status: available",
	"status:\tavailable", // Tab-separated (e.g., .be domains)
	"status:\tfree",      // Tab-separated
	"domain not found",
	"no object found",
	"nothing found",
	"no information available",
	"is available for registration",
	"is free",
	"domain status: no object found",
	"the queried object does not exist",
	"object does not exist",
	"no matching record",
	"this domain is available",
	"no match",
	"domain is available",
}

// Patterns for lines that contain volatile/dynamic data that should be filtered
var volatileLinePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^%`),                      // Comment lines
	regexp.MustCompile(`(?i)^>>>`),                    // WHOIS disclaimer markers
	regexp.MustCompile(`(?i)whois lookup made`),       // Query timestamp
	regexp.MustCompile(`(?i)last update of whois`),    // Database update timestamp
	regexp.MustCompile(`(?i)whois database was last`), // Database update timestamp
	regexp.MustCompile(`(?i)^#`),                      // Comment lines
	regexp.MustCompile(`(?i)query time:`),             // Query timing info
	regexp.MustCompile(`(?i)timestamp:`),              // Generic timestamps
	regexp.MustCompile(`(?i)^\s*$`),                   // Empty lines (normalize)
	regexp.MustCompile(`(?i)terms of use:`),           // Legal notices that may change
	regexp.MustCompile(`(?i)by the following terms`),  // Legal notices
	regexp.MustCompile(`(?i)whois server version`),    // Server version info
	regexp.MustCompile(`(?i)for more information`),    // Info notices
	regexp.MustCompile(`(?i)https?://`),               // URLs (often change)
	regexp.MustCompile(`(?i)please visit`),            // Instruction text
	regexp.MustCompile(`(?i)rate limit`),              // Rate limit messages
	regexp.MustCompile(`(?i)quota exceeded`),          // Quota messages
	regexp.MustCompile(`(?i)requests remaining`),      // Request count
	regexp.MustCompile(`(?i)database last updated`),   // Database timestamps
	regexp.MustCompile(`(?i)record last updated`),     // Record timestamps (not domain-specific)
	regexp.MustCompile(`(?i)>>> last update of`),      // Update markers
	regexp.MustCompile(`(?i)this query was served`),   // Query routing info
	regexp.MustCompile(`(?i)cached for`),              // Cache info
}

func main() {
	_ = godotenv.Load()

	workDir := os.Getenv("WORK_DIR")
	if workDir == "" {
		workDir = "/tmp/whois-watch"
	}

	// Parse configuration from environment
	if delay := os.Getenv("DOMAIN_CHECK_DELAY"); delay != "" {
		if d, err := time.ParseDuration(delay); err == nil {
			domainCheckDelay = d
		} else {
			logrus.Warnf("invalid DOMAIN_CHECK_DELAY value %q, using default %v", delay, domainCheckDelay)
		}
	}

	if ttl := os.Getenv("BOOTSTRAP_CACHE_TTL"); ttl != "" {
		if t, err := time.ParseDuration(ttl); err == nil {
			bootstrapCacheTTL = t
		} else {
			logrus.Warnf("invalid BOOTSTRAP_CACHE_TTL value %q, using default %v", ttl, bootstrapCacheTTL)
		}
	}

	domainsEnv := strings.TrimSpace(os.Getenv("WATCH_DOMAINS"))
	if domainsEnv == "" {
		logrus.Fatal("WATCH_DOMAINS environment variable is required")
	}

	// Split and filter empty entries
	rawDomains := strings.Split(domainsEnv, " ")
	var domains []string
	for _, d := range rawDomains {
		d = strings.TrimSpace(d)
		if d != "" {
			domains = append(domains, d)
		}
	}

	if len(domains) == 0 {
		logrus.Fatal("WATCH_DOMAINS must contain at least one domain")
	}

	logrus.Infof("whois-watcher configured with %d domains", len(domains))
	for _, d := range domains {
		logrus.Infof("  - %s", d)
	}
	logrus.Infof("domain check delay: %v", domainCheckDelay)

	err := os.MkdirAll(workDir, 0755)
	if err != nil {
		logrus.Fatalf("create work dir error: %v", err)
	}
	err = os.MkdirAll(path.Join(workDir, "diff"), 0755)
	if err != nil {
		logrus.Fatalf("create diff work dir error: %v", err)
	}
	err = os.MkdirAll(path.Join(workDir, "history"), 0755)
	if err != nil {
		logrus.Fatalf("create history work dir error: %v", err)
	}

	// Check if cron schedule is configured
	cronSchedule := os.Getenv("CRON_SCHEDULE")
	if cronSchedule != "" {
		runWithCron(cronSchedule, workDir, domains)
	} else {
		// Single run mode (for external cron/scheduler)
		runOnce(workDir, domains)
	}
}

// runOnce executes a single check cycle and exits
func runOnce(workDir string, domains []string) {
	exitCode := 0

	logrus.Info("starting whois check (single-run mode)")

	// Load or refresh RDAP bootstrap
	if err := loadOrRefreshBootstrap(workDir); err != nil {
		logrus.Errorf("failed to load RDAP bootstrap: %v", err)
		logrus.Warn("continuing with WHOIS-only mode")
	}

	err := run(workDir, domains)

	if err != nil {
		logrus.Errorf("run error: %v", err)
		exitCode = 1

		// try to send error message to discord
		sendErrorNotification(err)
	} else {
		logrus.Info("whois check completed successfully")
	}

	os.Exit(exitCode)
}

// runWithCron starts the cron scheduler and runs checks on schedule
func runWithCron(schedule string, workDir string, domains []string) {
	c := cron.New(cron.WithLogger(cron.VerbosePrintfLogger(logrus.StandardLogger())))

	// Validate and add the schedule
	_, err := c.AddFunc(schedule, func() {
		logrus.Info("starting scheduled whois check")

		// Load or refresh RDAP bootstrap
		if err := loadOrRefreshBootstrap(workDir); err != nil {
			logrus.Errorf("failed to load RDAP bootstrap: %v", err)
			logrus.Warn("continuing with WHOIS-only mode")
		}

		if err := run(workDir, domains); err != nil {
			logrus.Errorf("run error: %v", err)
			sendErrorNotification(err)
		} else {
			logrus.Info("scheduled whois check completed successfully")
		}
	})

	if err != nil {
		logrus.Fatalf("invalid CRON_SCHEDULE %q: %v", schedule, err)
	}

	logrus.Infof("starting cron scheduler with schedule: %s", schedule)

	// Run once immediately on startup
	logrus.Info("running initial check on startup")
	if err := loadOrRefreshBootstrap(workDir); err != nil {
		logrus.Errorf("failed to load RDAP bootstrap: %v", err)
		logrus.Warn("continuing with WHOIS-only mode")
	}
	if err := run(workDir, domains); err != nil {
		logrus.Errorf("initial run error: %v", err)
		sendErrorNotification(err)
	} else {
		logrus.Info("initial whois check completed successfully")
	}

	// Start the cron scheduler
	c.Start()

	// Log next scheduled run
	entries := c.Entries()
	if len(entries) > 0 {
		logrus.Infof("next scheduled run: %s", entries[0].Next.Format(time.RFC3339))
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logrus.Infof("received signal %v, shutting down...", sig)

	// Stop cron gracefully
	ctx := c.Stop()
	<-ctx.Done()

	logrus.Info("shutdown complete")
}

// sendErrorNotification sends an error notification to Discord
func sendErrorNotification(err error) {
	webhookURL := os.Getenv("NOTIFY_DISCORD_WEBHOOK")
	if webhookURL == "" {
		return
	}

	content := "# Error occurred"
	if os.Getenv("NOTIFY_DISCORD_USER_ID") != "" {
		content += "\n\n<@" + os.Getenv("NOTIFY_DISCORD_USER_ID") + ">"
	}
	errStr := err.Error()
	if len(errStr) > 1800 {
		logrus.Warnf("error message is too long, truncating")
		errStr = errStr[:1800]
	}
	content += "\n\n```\n" + errStr + "```"
	message := discordwebhook.Message{
		Content: &content,
	}

	if sendErr := discordwebhook.SendMessage(webhookURL, message); sendErr != nil {
		logrus.Errorf("failed to send error message to discord: %v", sendErr)
	}
}

// loadOrRefreshBootstrap loads the RDAP bootstrap from cache or fetches it fresh
func loadOrRefreshBootstrap(workDir string) error {
	tsFile := path.Join(workDir, bootstrapTSFile)
	cacheFile := path.Join(workDir, bootstrapCacheFile)

	// Check if cache is still valid
	needsRefresh := true
	if tsData, err := os.ReadFile(tsFile); err == nil {
		if ts, err := strconv.ParseInt(strings.TrimSpace(string(tsData)), 10, 64); err == nil {
			cacheTime := time.Unix(ts, 0)
			if time.Since(cacheTime) < bootstrapCacheTTL {
				needsRefresh = false
				logrus.Debugf("RDAP bootstrap cache is still valid (age: %v)", time.Since(cacheTime))
			}
		}
	}

	if !needsRefresh {
		// Load from cache
		if cacheData, err := os.ReadFile(cacheFile); err == nil {
			return parseBootstrapData(cacheData)
		}
		// Cache file missing, need to refresh
		needsRefresh = true
	}

	if needsRefresh {
		logrus.Info("fetching RDAP bootstrap from IANA...")
		data, err := fetchBootstrapData()
		if err != nil {
			// Try to use stale cache if available
			if cacheData, cacheErr := os.ReadFile(cacheFile); cacheErr == nil {
				logrus.Warnf("failed to fetch fresh bootstrap (%v), using stale cache", err)
				return parseBootstrapData(cacheData)
			}
			return fmt.Errorf("failed to fetch bootstrap and no cache available: %v", err)
		}

		// Save to cache
		if err := os.WriteFile(cacheFile, data, 0644); err != nil {
			logrus.Warnf("failed to save bootstrap cache: %v", err)
		}
		if err := os.WriteFile(tsFile, []byte(fmt.Sprintf("%d", time.Now().Unix())), 0644); err != nil {
			logrus.Warnf("failed to save bootstrap timestamp: %v", err)
		}

		return parseBootstrapData(data)
	}

	return nil
}

// fetchBootstrapData downloads the IANA RDAP bootstrap file
func fetchBootstrapData() ([]byte, error) {
	resp, err := httpClient.Get(bootstrapURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bootstrap: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bootstrap fetch returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// parseBootstrapData parses the IANA RDAP bootstrap JSON and populates the map
func parseBootstrapData(data []byte) error {
	var bootstrap struct {
		Version     string       `json:"version"`
		Publication string       `json:"publication"`
		Services    [][][]string `json:"services"`
	}

	if err := json.Unmarshal(data, &bootstrap); err != nil {
		return fmt.Errorf("failed to parse bootstrap JSON: %v", err)
	}

	rdapBootstrapLock.Lock()
	defer rdapBootstrapLock.Unlock()

	rdapBootstrap = make(map[string]string)

	for _, service := range bootstrap.Services {
		if len(service) < 2 {
			continue
		}

		tlds := service[0]
		urls := service[1]

		if len(urls) == 0 {
			continue
		}

		// Use the first URL (prefer HTTPS)
		rdapURL := urls[0]
		for _, u := range urls {
			if strings.HasPrefix(u, "https://") {
				rdapURL = u
				break
			}
		}

		// Ensure URL ends with /domain/ for domain lookups
		if !strings.HasSuffix(rdapURL, "/") {
			rdapURL += "/"
		}
		if !strings.HasSuffix(rdapURL, "domain/") {
			rdapURL += "domain/"
		}

		for _, tld := range tlds {
			rdapBootstrap[strings.ToLower(tld)] = rdapURL
		}
	}

	logrus.Infof("loaded RDAP bootstrap with %d TLD entries", len(rdapBootstrap))
	return nil
}

// getRDAPEndpoint returns the RDAP endpoint for a TLD, or empty string if not found
func getRDAPEndpoint(tld string) string {
	rdapBootstrapLock.RLock()
	defer rdapBootstrapLock.RUnlock()

	return rdapBootstrap[strings.ToLower(tld)]
}

func run(workDir string, domains []string) error {
	for i, domain := range domains {
		log := logrus.WithField("domain", domain)

		// Add delay between domains (except for the first one)
		if i > 0 && domainCheckDelay > 0 {
			log.Debugf("waiting %v before next domain check", domainCheckDelay)
			time.Sleep(domainCheckDelay)
		}

		// Validate domain format
		if !isValidDomain(domain) {
			log.Warnf("invalid domain format, skipping")
			continue
		}

		// Get previous status
		previousStatus := getPreviousStatus(workDir, domain)

		// Query whois/RDAP
		result, err := lookupDomain(domain)
		currentlyRegistered := true

		if err != nil {
			if errors.Is(err, ErrDomainNotRegistered) {
				currentlyRegistered = false
			} else {
				return fmt.Errorf("lookup error on domain %s: %v", domain, err)
			}
		}

		// Handle status changes
		if !currentlyRegistered {
			log.Debugf("domain is not registered")

			// Save unregistered status
			if err := saveStatus(workDir, domain, statusUnregistered); err != nil {
				log.Errorf("failed to save status: %v", err)
			}

			// Check if status changed from registered to unregistered
			if previousStatus == statusRegistered {
				log.Infof("domain became AVAILABLE (was registered)")

				// Save to history first
				historyContent := fmt.Sprintf("Domain became UNREGISTERED at %s\n", time.Now().Format(time.RFC3339))
				err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.txt", domain, time.Now().Unix())), []byte(historyContent), 0644)
				if err != nil {
					log.Errorf("write history file error: %v", err)
				}

				if err := notifyStatusChange(domain, false); err != nil {
					log.Errorf("failed to send status change notification: %v", err)
				}
			} else if previousStatus == "" {
				log.Infof("domain is not registered (initial check)")
			}

			continue
		}

		// Domain is registered
		log.Debugf("domain is registered")

		// Save registered status
		if err := saveStatus(workDir, domain, statusRegistered); err != nil {
			log.Errorf("failed to save status: %v", err)
		}

		// Check if status changed from unregistered to registered
		if previousStatus == statusUnregistered {
			log.Infof("domain became REGISTERED (was available)")

			// Save to history first
			historyContent := fmt.Sprintf("Domain became REGISTERED at %s\n\n%s", time.Now().Format(time.RFC3339), result)
			err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.txt", domain, time.Now().Unix())), []byte(historyContent), 0644)
			if err != nil {
				log.Errorf("write history file error: %v", err)
			}

			if err := notifyStatusChange(domain, true); err != nil {
				log.Errorf("failed to send status change notification: %v", err)
			}
		}

		// Now handle whois data changes for registered domains
		file, err := os.ReadFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("read file error on domain %s: %v", domain, err)
			}

			log.Infof("first whois data captured")
			err = os.WriteFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)), []byte(result), 0644)
			if err != nil {
				return fmt.Errorf("write file error on domain %s: %v", domain, err)
			}

			err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.txt", domain, time.Now().Unix())), []byte(result), 0644)
			if err != nil {
				log.Errorf("write history file error on domain %s: %v", domain, err)
			}
			continue
		}

		// Compare with previous whois data
		diff, err := diffLineByLine(string(file), result)
		if err != nil {
			return fmt.Errorf("diff error on domain %s: %v", domain, err)
		}

		// Update the current whois file
		err = os.WriteFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)), []byte(result), 0644)
		if err != nil {
			return fmt.Errorf("write file error on domain %s: %v", domain, err)
		}

		if len(diff) == 0 {
			log.Debugf("whois result is same as before")
			continue
		}

		log.Infof("whois data has been changed")

		log.Debugf("whois result is different from before:")
		for _, line := range strings.Split(diff, "\n") {
			log.Debugf("   %s", line)
		}

		err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.txt", domain, time.Now().Unix())), []byte(result), 0644)
		if err != nil {
			log.Errorf("write history file error: %v", err)
		}
		err = os.WriteFile(path.Join(workDir, "diff", fmt.Sprintf("%s.%d.diff", domain, time.Now().Unix())), []byte(diff), 0644)
		if err != nil {
			log.Errorf("write diff file error: %v", err)
		}

		messages := generateMessagesFromDiff(domain, diff)

		var errs []error
		for _, message := range messages {
			err = discordwebhook.SendMessage(os.Getenv("NOTIFY_DISCORD_WEBHOOK"), message)
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("send discord message error: %v", errs)
		}
	}

	return nil
}

// lookupDomain performs domain lookup using RDAP first, falling back to WHOIS
func lookupDomain(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	tld := strings.ToLower(parts[len(parts)-1])
	log := logrus.WithField("domain", domain)

	// Try RDAP first if we have an endpoint
	rdapEndpoint := getRDAPEndpoint(tld)
	if rdapEndpoint != "" {
		log.Debugf("trying RDAP lookup via %s", rdapEndpoint)
		result, err := queryRDAP(domain, rdapEndpoint)
		if err == nil {
			return result, nil
		}

		// Check if it's a "not registered" error - don't fall back for this
		if errors.Is(err, ErrDomainNotRegistered) {
			return "", err
		}

		// RDAP failed, try WHOIS as fallback
		log.Warnf("RDAP lookup failed (%v), falling back to WHOIS", err)
	}

	// Try WHOIS
	return whoisDomain(domain, tld)
}

// whoisDomain performs a WHOIS lookup for a domain
func whoisDomain(domain, tld string) (string, error) {
	log := logrus.WithField("domain", domain)
	log.Debugf("performing WHOIS lookup")

	result, err := whois.Whois(domain)
	if err != nil {
		// Check if error indicates no WHOIS server found
		if strings.Contains(err.Error(), "no whois server") {
			return "", fmt.Errorf("no WHOIS server found for TLD .%s and no RDAP endpoint available", tld)
		}
		return "", err
	}

	// Check if WHOIS server returned "TLD is not supported"
	if strings.Contains(strings.ToLower(result), "tld is not supported") {
		return "", fmt.Errorf("WHOIS server does not support TLD .%s and no RDAP endpoint available", tld)
	}

	// Check if domain is not registered
	lowerResult := strings.ToLower(result)
	for _, pattern := range notRegisteredPatterns {
		if strings.Contains(lowerResult, pattern) {
			return "", ErrDomainNotRegistered
		}
	}

	// Filter out volatile lines that change between queries
	lines := strings.Split(result, "\n")
	var filteredLines []string

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines
		if trimmedLine == "" {
			continue
		}

		// Check against volatile patterns
		shouldSkip := false
		for _, pattern := range volatileLinePatterns {
			if pattern.MatchString(line) {
				shouldSkip = true
				break
			}
		}

		if !shouldSkip {
			filteredLines = append(filteredLines, line)
		}
	}

	return strings.Join(filteredLines, "\n") + "\n", nil
}

// queryRDAP queries the RDAP service for domain information
func queryRDAP(domain, baseURL string) (string, error) {
	url := baseURL + domain

	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("RDAP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		retryAfter := resp.Header.Get("Retry-After")
		if retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil {
				logrus.Warnf("RDAP rate limited, Retry-After: %d seconds", seconds)
				time.Sleep(time.Duration(seconds) * time.Second)
				// Retry once
				resp, err = httpClient.Get(url)
				if err != nil {
					return "", fmt.Errorf("RDAP retry failed: %w", err)
				}
				defer resp.Body.Close()
			}
		} else {
			// No Retry-After header, wait 5 seconds and retry
			logrus.Warn("RDAP rate limited, waiting 5 seconds before retry")
			time.Sleep(5 * time.Second)
			resp, err = httpClient.Get(url)
			if err != nil {
				return "", fmt.Errorf("RDAP retry failed: %w", err)
			}
			defer resp.Body.Close()
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read RDAP response: %w", err)
	}

	if resp.StatusCode == 404 {
		return "", ErrDomainNotRegistered
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("RDAP returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse RDAP JSON response
	var rdapResp map[string]interface{}
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return "", fmt.Errorf("failed to parse RDAP response: %w", err)
	}

	// Check for error responses
	if errorCode, ok := rdapResp["errorCode"]; ok {
		if code, ok := errorCode.(float64); ok && code == 404 {
			return "", ErrDomainNotRegistered
		}
	}

	// Convert RDAP response to a stable text format for diffing
	return formatRDAPResponse(rdapResp), nil
}

// getPreviousStatus reads the previous registration status for a domain
func getPreviousStatus(workDir, domain string) string {
	data, err := os.ReadFile(path.Join(workDir, fmt.Sprintf("%s.status", domain)))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveStatus saves the current registration status for a domain
func saveStatus(workDir, domain, status string) error {
	return os.WriteFile(path.Join(workDir, fmt.Sprintf("%s.status", domain)), []byte(status), 0644)
}

// notifyStatusChange sends a Discord notification when domain registration status changes
func notifyStatusChange(domain string, becameRegistered bool) error {
	webhookURL := os.Getenv("NOTIFY_DISCORD_WEBHOOK")
	if webhookURL == "" {
		return nil
	}

	var content string
	if becameRegistered {
		content = "# Domain `" + domain + "` is now REGISTERED"
		content += "\n\nThis domain was previously available and has now been registered by someone."
	} else {
		content = "# Domain `" + domain + "` is now AVAILABLE"
		content += "\n\nThis domain was previously registered and is now available for registration!"
	}

	if os.Getenv("NOTIFY_DISCORD_USER_ID") != "" {
		content += "\n\n<@" + os.Getenv("NOTIFY_DISCORD_USER_ID") + ">"
	}

	message := discordwebhook.Message{
		Content: &content,
	}

	return discordwebhook.SendMessage(webhookURL, message)
}

func diffLineByLine(from, to string) (string, error) {
	workDir, err := os.MkdirTemp("", "diff")
	defer os.RemoveAll(workDir)
	if err != nil {
		return "", err
	}

	fromFile := path.Join(workDir, "from.txt")
	toFile := path.Join(workDir, "to.txt")

	err = os.WriteFile(fromFile, []byte(from), 0644)
	if err != nil {
		return "", err
	}
	err = os.WriteFile(toFile, []byte(to), 0644)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("diff", fromFile, toFile)
	out, err := cmd.Output()
	if err != nil && cmd.ProcessState.ExitCode() != 1 {
		return "", err
	}

	return string(out), nil
}

// formatRDAPResponse converts RDAP JSON to a stable text format
func formatRDAPResponse(rdap map[string]interface{}) string {
	var lines []string

	// Domain name
	if name, ok := rdap["ldhName"].(string); ok {
		lines = append(lines, fmt.Sprintf("Domain Name: %s", strings.ToUpper(name)))
	}

	// Handle/ID
	if handle, ok := rdap["handle"].(string); ok {
		lines = append(lines, fmt.Sprintf("Registry Domain ID: %s", handle))
	}

	// Status
	if statuses, ok := rdap["status"].([]interface{}); ok {
		for _, s := range statuses {
			if status, ok := s.(string); ok {
				lines = append(lines, fmt.Sprintf("Domain Status: %s", status))
			}
		}
	}

	// Nameservers
	if nameservers, ok := rdap["nameservers"].([]interface{}); ok {
		for _, ns := range nameservers {
			if nsMap, ok := ns.(map[string]interface{}); ok {
				if name, ok := nsMap["ldhName"].(string); ok {
					lines = append(lines, fmt.Sprintf("Name Server: %s", strings.ToLower(name)))
				}
			}
		}
	}

	// Events (creation, expiration, last update)
	if events, ok := rdap["events"].([]interface{}); ok {
		for _, e := range events {
			if event, ok := e.(map[string]interface{}); ok {
				action, _ := event["eventAction"].(string)
				date, _ := event["eventDate"].(string)
				switch action {
				case "registration":
					lines = append(lines, fmt.Sprintf("Creation Date: %s", date))
				case "expiration":
					lines = append(lines, fmt.Sprintf("Registry Expiry Date: %s", date))
				case "last changed":
					lines = append(lines, fmt.Sprintf("Updated Date: %s", date))
				}
			}
		}
	}

	// Entities (registrar, registrant, etc.)
	if entities, ok := rdap["entities"].([]interface{}); ok {
		for _, e := range entities {
			if entity, ok := e.(map[string]interface{}); ok {
				roles, _ := entity["roles"].([]interface{})
				for _, r := range roles {
					role, _ := r.(string)
					if role == "registrar" {
						if handle, ok := entity["handle"].(string); ok {
							lines = append(lines, fmt.Sprintf("Registrar IANA ID: %s", handle))
						}
						if vcards, ok := entity["vcardArray"].([]interface{}); ok && len(vcards) > 1 {
							if vcardData, ok := vcards[1].([]interface{}); ok {
								for _, item := range vcardData {
									if arr, ok := item.([]interface{}); ok && len(arr) >= 4 {
										if arr[0] == "fn" {
											lines = append(lines, fmt.Sprintf("Registrar: %v", arr[3]))
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// DNSSEC
	if secureDNS, ok := rdap["secureDNS"].(map[string]interface{}); ok {
		if delegationSigned, ok := secureDNS["delegationSigned"].(bool); ok {
			if delegationSigned {
				lines = append(lines, "DNSSEC: signedDelegation")
			} else {
				lines = append(lines, "DNSSEC: unsigned")
			}
		}
	}

	return strings.Join(lines, "\n") + "\n"
}

// isValidDomain checks if the domain string has a valid format
func isValidDomain(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}

	// Basic validation: must have at least one dot and no spaces
	if !strings.Contains(domain, ".") || strings.Contains(domain, " ") {
		return false
	}

	// Check for valid domain characters
	validDomain := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	return validDomain.MatchString(domain)
}

func generateMessagesFromDiff(domain string, diff string) []discordwebhook.Message {
	header := "# Domain `" + domain + "` has been changed"
	if os.Getenv("NOTIFY_DISCORD_USER_ID") != "" {
		header += "\n\n<@" + os.Getenv("NOTIFY_DISCORD_USER_ID") + ">"
	}
	header += "\n\n"

	lines := strings.Split(diff, "\n")
	var lineBlocks []string
	currentLineBlock := ""
	for _, line := range lines {
		if len(lineBlocks) == 0 && len(header)+len(currentLineBlock)+len(line) > 1950 {
			lineBlocks = append(lineBlocks, currentLineBlock)
			currentLineBlock = ""
		}

		if len(lineBlocks) > 0 && len(currentLineBlock)+len(line) > 1950 {
			lineBlocks = append(lineBlocks, currentLineBlock)
			currentLineBlock = ""
		}

		if len(currentLineBlock) > 0 {
			currentLineBlock += "\n"
		}
		currentLineBlock += line
	}
	if len(currentLineBlock) > 0 {
		lineBlocks = append(lineBlocks, currentLineBlock)
	}

	var messages []discordwebhook.Message

	for i, lineBlock := range lineBlocks {
		content := ""
		if i == 0 {
			content = header
			content += "```diff\n" + lineBlock + "\n```"
		} else {
			content = "```diff\n" + lineBlock + "\n```"
		}

		messages = append(messages, discordwebhook.Message{
			Content: &content,
		})
	}

	return messages
}
