package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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

const EmailPattern = `\b((?i)(?:[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))\b`
const SubDomainPattern = `\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)\b`
const UUIDPattern = `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`
const UUIDPatternUpperCase = `\b([0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12})\b`

const RegixPattern = "0-9a-z"
const AlphaNumPattern = "0-9a-zA-Z"
const HexPattern = "0-9a-f"

var keywords = []string{"pass", "token", "cred", "secret", "key"}

func BuildRegex(pattern string, specialChar string, length int) string {
	return fmt.Sprintf(`\b([%s%s]{%s})\b`, pattern, specialChar, strconv.Itoa(length))
}

func BuildRegexJWT(firstRange, secondRange, thirdRange string) string {
	if RangeValidation(firstRange) || RangeValidation(secondRange) || RangeValidation(thirdRange) {
		panic("Min value should not be greater than or equal to max")
	}
	return fmt.Sprintf(`\b(ey[%s]{%s}.ey[%s-\/_]{%s}.[%s-\/_]{%s})\b`, AlphaNumPattern, firstRange, AlphaNumPattern, secondRange, AlphaNumPattern, thirdRange)
}

func RangeValidation(rangeInput string) bool {
	range_split := strings.Split(rangeInput, ",")
	range_min, _ := strconv.ParseInt(strings.TrimSpace(range_split[0]), 10, 0)
	range_max, _ := strconv.ParseInt(strings.TrimSpace(range_split[1]), 10, 0)
	return range_min >= range_max
}

// PrefixRegex ensures that at least one of the given keywords is within
// 40 characters of the capturing group that follows.
// This can help prevent false positives.
func prefixRegex(keywords []string) string {
	pre := `(?i:`
	middle := strings.Join(keywords, "|")
	post := `)(?:.|[\n\r]){0,40}?`
	return pre + middle + post
}