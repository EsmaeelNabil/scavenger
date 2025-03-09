package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"
)

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
	for _, pattern := range NewSecretPatterns {
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			// Extract matched value
			var value string
			if len(match) > 1 && match[1] != "" {
				value = match[1] // Use the first capture group if it exists
			} else {
				value = match[0] // Otherwise use the full match
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
