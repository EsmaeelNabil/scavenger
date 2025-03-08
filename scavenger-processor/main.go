package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// WebsiteData represents all data collected from a website
type WebsiteData struct {
	URL         string           `json:"url"`
	Title       string           `json:"title"`
	Timestamp   float64          `json:"timestamp"`
	Resources   []Resource       `json:"resources"`
	ContentData map[string]any   `json:"contentData"`
	Cookies     []map[string]any `json:"cookies"`               // Changed from string to any
	CaptureTime float64          `json:"captureTime,omitempty"` // Changed to float64
}

type Resource struct {
	URL          string  `json:"url"`
	Type         string  `json:"type"`
	ContentType  string  `json:"contentType"`
	Method       string  `json:"method"`
	StatusCode   int     `json:"statusCode"`
	FromCache    bool    `json:"fromCache"`
	Timestamp    float64 `json:"timestamp"`
	Size         int     `json:"size"`
	Content      string  `json:"content,omitempty"`
	RedirectedTo string  `json:"redirectedTo,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// AnalysisResult contains the processed data
type AnalysisResult struct {
	URL               string                    `json:"url"`
	Title             string                    `json:"title"`
	AnalysisTimestamp string                    `json:"analysisTimestamp"`
	ResourceStats     ResourceStats             `json:"resourceStats"`
	ContentTypes      map[string]int            `json:"contentTypes"`
	Domains           map[string]int            `json:"domains"`
	CodeAnalysis      map[string]map[string]any `json:"codeAnalysis"`
	Comments          []Comment                 `json:"comments"`
	StorageData       map[string]int            `json:"storageData"`
	CookieAnalysis    map[string]int            `json:"cookieAnalysis"`
	SecurityIssues    []SecurityIssue           `json:"securityIssues"`
	PerformanceInfo   map[string]any            `json:"performanceInfo"`
	DetectedSecrets   []DetectedSecret          `json:"detectedSecrets"`
}

// DetectedSecret represents a secret or sensitive information found in the resources
type DetectedSecret struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	ResourceURL string `json:"resourceUrl"`
	Context     string `json:"context"`
	Confidence  string `json:"confidence"` // high, medium, low
}

// ResourceStats contains counts of various resource types
type ResourceStats struct {
	TotalResources int `json:"totalResources"`
	HTMLCount      int `json:"htmlCount"`
	JSCount        int `json:"jsCount"`
	CSSCount       int `json:"cssCount"`
	JSONCount      int `json:"jsonCount"`
	XMLCount       int `json:"xmlCount"`
	FontCount      int `json:"fontCount"`
	ImageCount     int `json:"imageCount"`
	OtherCount     int `json:"otherCount"`
}

// Comment represents a code comment
type Comment struct {
	Type     string `json:"type"`
	Content  string `json:"content"`
	Source   string `json:"source"`
	Language string `json:"language"`
}

// SecurityIssue represents a detected security concern
type SecurityIssue struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
}

// RegexPattern defines a pattern to search for secrets
type RegexPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Description string
	Confidence  string
}

// Configuration options
var (
	saveToFiles   bool
	outputDir     string
	verboseOutput bool
)

// Sensitive patterns collection
var secretPatterns = []RegexPattern{
	{
		Name:        "AWS Access Key",
		Regex:       regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		Description: "AWS Access Key ID",
		Confidence:  "high",
	},
	{
		Name:        "AWS Secret Key",
		Regex:       regexp.MustCompile(`(?i)(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)`),
		Description: "Potential AWS Secret Access Key",
		Confidence:  "medium",
	},
	{
		Name:        "API Key",
		Regex:       regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token)['":\s]*([^\s,;'"\[\]]{16,})`),
		Description: "Generic API key",
		Confidence:  "medium",
	},
	{
		Name:        "Google API Key",
		Regex:       regexp.MustCompile(`(?i)AIza[0-9A-Za-z-_]{35}`),
		Description: "Google API Key",
		Confidence:  "high",
	},
	{
		Name:        "Private Key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN [A-Z]+ PRIVATE KEY-----`),
		Description: "Private key material",
		Confidence:  "high",
	},
	{
		Name:        "Authorization Header",
		Regex:       regexp.MustCompile(`(?i)authorization:\s*(?:bearer|basic|token)\s+([a-zA-Z0-9._\-]+)`),
		Description: "Authorization header with token",
		Confidence:  "high",
	},
	{
		Name:        "JWT Token",
		Regex:       regexp.MustCompile(`(?i)eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}`),
		Description: "JWT Token",
		Confidence:  "medium",
	},
	{
		Name:        "Password Field",
		Regex:       regexp.MustCompile(`(?i)(?:password|passwd|pwd)[\s]*[=:]\s*['"]([^'"]{3,})['"]\s*[,;]`),
		Description: "Hardcoded password in code",
		Confidence:  "medium",
	},
	{
		Name:        "GitHub Token",
		Regex:       regexp.MustCompile(`(?i)(?:github|gh)[_\-\s](?:token|key)[_\-\s]*[=:]\s*['"]([a-zA-Z0-9_]{35,40})['"]`),
		Description: "GitHub token or personal access token",
		Confidence:  "high",
	},
}

func main() {
	// Parse command line flags
	flag.BoolVar(&saveToFiles, "save", false, "Save detected secrets to files")
	flag.StringVar(&outputDir, "output", "detected_secrets", "Directory for saving detected secrets")
	flag.BoolVar(&verboseOutput, "verbose", false, "Enable verbose logging")
	flag.Parse()

	// Create output directory if it doesn't exist and saving is enabled
	if saveToFiles {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Fatalf("Failed to create output directory: %v", err)
		}
		log.Printf("Saving detected secrets to directory: %s", outputDir)
	}

	r := mux.NewRouter()

	// API endpoint for receiving website data
	r.HandleFunc("/api/resources", handleResourceUpload).Methods("POST", "OPTIONS")

	// Add CORS middleware
	corsMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow requests from extensions (chrome-extension://)
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	// Start server
	serverAddress := ":8080"
	log.Printf("Starting server with secret scanning enabled on %s", serverAddress)
	if saveToFiles {
		log.Printf("Secret saving enabled. Full data saving (NO SIZE LIMITS) to output directory: %s", outputDir)
	}
	log.Fatal(http.ListenAndServe(serverAddress, corsMiddleware(r)))
}

func handleResourceUpload(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request details
	log.Printf("Received request from: %s", r.RemoteAddr)
	log.Printf("Content-Type: %s", r.Header.Get("Content-Type"))

	// Read the request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Restore the body for the decoder
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Log the first part of the request for debugging
	log.Printf("Request body sample: %s", string(bodyBytes[:min(len(bodyBytes), 500)]))

	// Decode the JSON payload
	var data WebsiteData
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&data)
	if err != nil {
		log.Printf("JSON decode error: %v", err)
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Process the data
	log.Printf("Successfully decoded data for URL: %s", data.URL)
	log.Printf("Received %d resources", len(data.Resources))

	// Save the original data if saving is enabled
	if saveToFiles {
		if err := saveOriginalData(data, bodyBytes); err != nil {
			log.Printf("Error saving original data: %v", err)
		}
	}

	for _, value := range data.Resources {
		//if strings.Contains(value.ContentType, "json") {
		//}
		fmt.Println("  ", value.ContentType)
		fmt.Println("  ", value.URL)
		fmt.Println("  ", value.Size)
		fmt.Println("----")
	}

	//// Analyze the website data for secrets
	//result := analyzeWebsiteData(data)
	//
	//// Log summary of findings
	//log.Printf("Analysis complete: Found %d secrets in %s",
	//	len(result.DetectedSecrets), data.URL)
	//
	//// Save results to file if enabled and secrets were found
	//if saveToFiles && len(result.DetectedSecrets) > 0 {
	//	if err := saveResultsToFile(result); err != nil {
	//		log.Printf("Error saving results to file: %v", err)
	//	}
	//}

	// Return the analysis result
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("result")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func analyzeWebsiteData(data WebsiteData) AnalysisResult {
	// Create a new analysis result
	result := AnalysisResult{
		URL:               data.URL,
		Title:             data.Title,
		AnalysisTimestamp: time.Now().Format(time.RFC3339),
		ResourceStats:     calculateResourceStats(data.Resources),
		ContentTypes:      make(map[string]int),
		Domains:           make(map[string]int),
		CodeAnalysis:      make(map[string]map[string]any),
		Comments:          []Comment{},
		StorageData:       make(map[string]int),
		CookieAnalysis:    make(map[string]int),
		SecurityIssues:    []SecurityIssue{},
		PerformanceInfo:   make(map[string]any),
		DetectedSecrets:   []DetectedSecret{},
	}

	// Scan all resources for secrets
	for _, resource := range data.Resources {
		// Only scan textual resources
		if isTextualResource(resource.ContentType) && resource.Content != "" {
			// Scan the resource content
			secrets := scanForSecrets(resource.Content, resource.URL)
			// Add to the results if any secrets found
			if len(secrets) > 0 {
				result.DetectedSecrets = append(result.DetectedSecrets, secrets...)
				log.Printf("Found %d secrets in %s", len(secrets), resource.URL)
			}
		}

		// Track content types
		result.ContentTypes[resource.ContentType]++
	}

	// Scan cookies for sensitive information
	if len(data.Cookies) > 0 {
		cookieSecrets := scanCookiesForSecrets(data.Cookies, data.URL)
		if len(cookieSecrets) > 0 {
			result.DetectedSecrets = append(result.DetectedSecrets, cookieSecrets...)
			log.Printf("Found %d secrets in cookies", len(cookieSecrets))
		}
	}

	// Scan ContentData for sensitive information
	if len(data.ContentData) > 0 {
		contentDataSecrets := scanContentDataForSecrets(data.ContentData, data.URL)
		if len(contentDataSecrets) > 0 {
			result.DetectedSecrets = append(result.DetectedSecrets, contentDataSecrets...)
			log.Printf("Found %d secrets in content data", len(contentDataSecrets))
		}
	}

	return result
}

func calculateResourceStats(resources []Resource) ResourceStats {
	stats := ResourceStats{
		TotalResources: len(resources),
	}

	for _, resource := range resources {
		contentType := strings.ToLower(resource.ContentType)

		if strings.Contains(contentType, "html") {
			stats.HTMLCount++
		} else if strings.Contains(contentType, "javascript") {
			stats.JSCount++
		} else if strings.Contains(contentType, "css") {
			stats.CSSCount++
		} else if strings.Contains(contentType, "json") {
			stats.JSONCount++
		} else if strings.Contains(contentType, "xml") {
			stats.XMLCount++
		} else if strings.Contains(contentType, "font") {
			stats.FontCount++
		} else if strings.Contains(contentType, "image") {
			stats.ImageCount++
		} else {
			stats.OtherCount++
		}
	}

	return stats
}

func isTextualResource(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "text") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "html") ||
		strings.Contains(contentType, "css")
}

func scanForSecrets(content string, resourceURL string) []DetectedSecret {
	var results []DetectedSecret

	// Apply each regex pattern to the content
	for _, pattern := range secretPatterns {
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			// Extract matched value
			var value string
			if len(match) > 1 && match[1] != "" {
				value = redactSecret(match[1]) // Use the first capture group if it exists
			} else {
				value = redactSecret(match[0]) // Otherwise use the full match
			}

			// Get some surrounding context
			context := extractContext(content, match[0])

			// Create a detected secret
			secret := DetectedSecret{
				Type:        pattern.Name,
				Value:       value,
				ResourceURL: resourceURL,
				Context:     context,
				Confidence:  pattern.Confidence,
			}

			results = append(results, secret)
		}
	}

	return results
}

func scanCookiesForSecrets(cookies []map[string]any, siteURL string) []DetectedSecret {
	var results []DetectedSecret

	// Convert cookies to JSON string for scanning
	cookiesJSON, err := json.Marshal(cookies)
	if err != nil {
		log.Printf("Error marshaling cookies: %v", err)
		return results
	}

	// Use the general secret scanning function
	return scanForSecrets(string(cookiesJSON), siteURL+" (cookies)")
}

func scanContentDataForSecrets(contentData map[string]any, siteURL string) []DetectedSecret {
	var results []DetectedSecret

	// Convert content data to JSON string for scanning
	contentDataJSON, err := json.Marshal(contentData)
	if err != nil {
		log.Printf("Error marshaling content data: %v", err)
		return results
	}

	// Use the general secret scanning function
	return scanForSecrets(string(contentDataJSON), siteURL+" (content data)")
}

func extractContext(content string, match string) string {
	// Find the position of the match in the content
	pos := strings.Index(content, match)
	if pos == -1 {
		return ""
	}

	// Get some context before and after the match
	contextStart := max(0, pos-50)
	contextEnd := min(len(content), pos+len(match)+50)

	// Extract the context
	context := content[contextStart:contextEnd]

	// Replace line breaks with spaces
	context = strings.ReplaceAll(context, "\n", " ")
	context = strings.ReplaceAll(context, "\r", "")

	// If we truncated the context, add ellipsis
	if contextStart > 0 {
		context = "..." + context
	}
	if contextEnd < len(content) {
		context = context + "..."
	}

	return context
}

func redactSecret(secret string) string {
	return secret
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// saveOriginalData saves the original data received from the extension
func saveOriginalData(data WebsiteData, rawBytes []byte) error {
	// Create a sanitized filename from the URL
	parsedURL, err := url.Parse(data.URL)
	if err != nil {
		return fmt.Errorf("invalid URL for file saving: %v", err)
	}

	// Create a base filename from the host and path
	baseFilename := parsedURL.Hostname()
	if baseFilename == "" {
		baseFilename = "unknown-host"
	}

	// Add timestamp for uniqueness
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s-%s", baseFilename, timestamp)

	// Sanitize the filename by removing invalid characters
	filename = sanitizeFilename(filename)

	// Ensure the output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Save both raw JSON and structured data

	// 1. Save the raw JSON exactly as received
	rawPath := filepath.Join(outputDir, filename+"-raw.json")
	rawPath = ensureUniqueFilename(rawPath)

	if err := os.WriteFile(rawPath, rawBytes, 0644); err != nil {
		return fmt.Errorf("error writing raw data file: %v", err)
	}
	log.Printf("Saved raw data to: %s (%d bytes)", rawPath, len(rawBytes))

	// 2. Save the structured data with pretty formatting
	structuredPath := filepath.Join(outputDir, filename+"-original.json")
	structuredPath = ensureUniqueFilename(structuredPath)

	// Create a modified copy with truncated contents for large resources
	// This prevents massive JSON files when there's a lot of content
	dataCopy := sanitizeForStorage(data)

	if err := writeJSONToFile(dataCopy, structuredPath); err != nil {
		return fmt.Errorf("failed to write structured data: %v", err)
	}
	log.Printf("Saved structured original data to: %s", structuredPath)

	// 3. Save a summary file with just resource metadata (no content)
	summaryData := createDataSummary(data)
	summaryPath := filepath.Join(outputDir, filename+"-summary.json")
	summaryPath = ensureUniqueFilename(summaryPath)

	if err := writeJSONToFile(summaryData, summaryPath); err != nil {
		return fmt.Errorf("failed to write summary data: %v", err)
	}
	log.Printf("Saved data summary to: %s", summaryPath)

	return nil
}

// sanitizeForStorage creates a copy of the WebsiteData with full content
func sanitizeForStorage(data WebsiteData) WebsiteData {
	// Make a deep copy
	dataCopy := data

	// Create new resources slice
	dataCopy.Resources = make([]Resource, len(data.Resources))

	// Copy each resource with full content
	for i, res := range data.Resources {
		dataCopy.Resources[i] = res
	}

	return dataCopy
}

// createDataSummary creates a summary of the data without the large content fields
func createDataSummary(data WebsiteData) map[string]interface{} {
	// Create a summary structure
	summary := map[string]interface{}{
		"url":           data.URL,
		"title":         data.Title,
		"timestamp":     data.Timestamp,
		"captureTime":   data.CaptureTime,
		"resourceCount": len(data.Resources),
		"cookieCount":   len(data.Cookies),
		"resources":     make([]map[string]interface{}, 0, len(data.Resources)),
	}

	// Add resource metadata (excluding content)
	for _, res := range data.Resources {
		resMeta := map[string]interface{}{
			"url":         res.URL,
			"type":        res.Type,
			"contentType": res.ContentType,
			"method":      res.Method,
			"statusCode":  res.StatusCode,
			"fromCache":   res.FromCache,
			"timestamp":   res.Timestamp,
			"size":        res.Size,
		}

		if res.RedirectedTo != "" {
			resMeta["redirectedTo"] = res.RedirectedTo
		}

		if res.Error != "" {
			resMeta["error"] = res.Error
		}

		summary["resources"] = append(summary["resources"].([]map[string]interface{}), resMeta)
	}

	return summary
}

// saveResultsToFile saves the analysis results to files
func saveResultsToFile(result AnalysisResult) error {
	// Ensure we have detected secrets to save
	if len(result.DetectedSecrets) == 0 {
		return nil // Nothing to save
	}

	// Create a sanitized filename from the URL
	parsedURL, err := url.Parse(result.URL)
	if err != nil {
		return fmt.Errorf("invalid URL for file saving: %v", err)
	}

	// Create a base filename from the host and path
	baseFilename := parsedURL.Hostname()
	if baseFilename == "" {
		baseFilename = "unknown-host"
	}

	// Add timestamp for uniqueness
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s-%s", baseFilename, timestamp)

	// Sanitize the filename by removing invalid characters
	filename = sanitizeFilename(filename)

	// Ensure the output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Save the full analysis result
	fullResultPath := filepath.Join(outputDir, filename+"-full-analysis.json")

	// Check if file already exists and append a number if it does
	fullResultPath = ensureUniqueFilename(fullResultPath)

	if err := writeJSONToFile(result, fullResultPath); err != nil {
		return fmt.Errorf("failed to write full analysis: %v", err)
	}
	log.Printf("Saved full analysis to: %s", fullResultPath)

	// Save just the secrets to a separate file for easier review
	secretsOnly := struct {
		URL             string           `json:"url"`
		Title           string           `json:"title"`
		Timestamp       string           `json:"timestamp"`
		DetectedSecrets []DetectedSecret `json:"detectedSecrets"`
		Count           int              `json:"count"`
	}{
		URL:             result.URL,
		Title:           result.Title,
		Timestamp:       result.AnalysisTimestamp,
		DetectedSecrets: result.DetectedSecrets,
		Count:           len(result.DetectedSecrets),
	}

	secretsPath := filepath.Join(outputDir, filename+"-secrets-only.json")
	secretsPath = ensureUniqueFilename(secretsPath)

	if err := writeJSONToFile(secretsOnly, secretsPath); err != nil {
		return fmt.Errorf("failed to write secrets file: %v", err)
	}
	log.Printf("Saved %d detected secrets to: %s", len(result.DetectedSecrets), secretsPath)

	// Generate a simple text report for human review
	reportPath := filepath.Join(outputDir, filename+"-secrets-report.txt")
	reportPath = ensureUniqueFilename(reportPath)

	if err := writeTextReport(result, reportPath); err != nil {
		return fmt.Errorf("failed to write text report: %v", err)
	}
	log.Printf("Saved human-readable report to: %s", reportPath)

	return nil
}

// ensureUniqueFilename makes sure the filename doesn't exist by appending a number if needed
func ensureUniqueFilename(path string) string {
	// If file doesn't exist, return the original path
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}

	// File exists, append a counter
	ext := filepath.Ext(path)
	base := path[:len(path)-len(ext)]

	counter := 1
	for {
		newPath := fmt.Sprintf("%s-%d%s", base, counter, ext)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
		counter++
	}
}

// writeJSONToFile marshals the provided data to JSON and writes it to the specified file
func writeJSONToFile(data interface{}, filepath string) error {
	// Marshal the data with pretty formatting
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Write to file
	err = os.WriteFile(filepath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}

	return nil
}

// sanitizeFilename removes characters that aren't allowed in filenames
func sanitizeFilename(filename string) string {
	// Replace characters that aren't allowed in filenames
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "",
		"?", "",
		"\"", "",
		"<", "",
		">", "",
		"|", "",
		" ", "_",
	)
	return replacer.Replace(filename)
}

// writeTextReport creates a human-readable text report of the detected secrets
func writeTextReport(result AnalysisResult, filepath string) error {
	// Check if there are any secrets to report
	if len(result.DetectedSecrets) == 0 {
		return fmt.Errorf("no secrets to write in report")
	}

	var report strings.Builder

	// Write report header
	report.WriteString("DETECTED SECRETS REPORT\n")
	report.WriteString("======================\n\n")
	report.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
	report.WriteString(fmt.Sprintf("Title: %s\n", result.Title))
	report.WriteString(fmt.Sprintf("Analysis timestamp: %s\n", result.AnalysisTimestamp))
	report.WriteString(fmt.Sprintf("Total secrets detected: %d\n\n", len(result.DetectedSecrets)))

	// Group secrets by type
	secretsByType := make(map[string][]DetectedSecret)
	for _, secret := range result.DetectedSecrets {
		secretsByType[secret.Type] = append(secretsByType[secret.Type], secret)
	}

	// Write secrets by type
	for secretType, secrets := range secretsByType {
		report.WriteString(fmt.Sprintf("## %s (%d found)\n", secretType, len(secrets)))

		for i, secret := range secrets {
			report.WriteString(fmt.Sprintf("  %d. Value: %s\n", i+1, secret.Value))
			report.WriteString(fmt.Sprintf("     Resource: %s\n", secret.ResourceURL))
			report.WriteString(fmt.Sprintf("     Confidence: %s\n", secret.Confidence))
			report.WriteString(fmt.Sprintf("     Context: %s\n\n", secret.Context))
		}
	}

	// Write recommendations
	report.WriteString("RECOMMENDATIONS\n")
	report.WriteString("===============\n")
	report.WriteString("1. Review all detected secrets and assess their exposure risk\n")
	report.WriteString("2. Revoke and rotate any exposed credentials\n")
	report.WriteString("3. Implement secrets management and avoid hardcoding credentials\n")
	report.WriteString("4. Consider using environment variables or a dedicated secrets manager\n")
	report.WriteString("\n---\n")
	report.WriteString(fmt.Sprintf("Report generated by Website Secret Scanner on %s\n",
		time.Now().Format(time.RFC1123)))

	// Write to file
	return os.WriteFile(filepath, []byte(report.String()), 0644)
}
