package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

// Global variables
var (
	saveToFiles   bool
	outputDir     string
	verboseOutput bool

	// Cache for analysis results
	resultsMutex sync.RWMutex
	resultsCache = make(map[string]AnalysisResult)
)

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

	// API endpoints
	r.HandleFunc("/api/upload", handleResourceUpload).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/uploadAndSave", handleResourceUploadAndSave).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/resources", handleGetAllResources).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/clear", handleClearAllResources).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/save", handleSaveAllResources).Methods("GET", "OPTIONS")

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

	// Log resource details if verbose
	if verboseOutput {
		for _, value := range data.Resources {
			fmt.Println("  ", value.ContentType)
			fmt.Println("  ", value.URL)
			fmt.Println("  ", value.Size)
			fmt.Println("----")
		}
	}

	// Analyze the website data for secrets
	result := analyzeWebsiteData(data)

	// Log summary of findings
	log.Printf("Analysis complete: Found %d secrets in %s",
		len(result.DetectedSecrets), data.URL)

	// Store result in the cache
	resultsMutex.Lock()
	resultsCache[data.URL] = result
	resultsMutex.Unlock()

	// Return the analysis result
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Analysis complete")

}

func handleResourceUploadAndSave(w http.ResponseWriter, r *http.Request) {
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

	// Save the original data
	if err := saveOriginalData(data, bodyBytes); err != nil {
		log.Printf("Error saving original data: %v", err)
	}

	// Log resource details if verbose
	if verboseOutput {
		for _, value := range data.Resources {
			fmt.Println("  ", value.ContentType)
			fmt.Println("  ", value.URL)
			fmt.Println("  ", value.Size)
			fmt.Println("----")
		}
	}

	// Analyze the website data for secrets
	result := analyzeWebsiteData(data)

	// Log summary of findings
	log.Printf("Analysis complete: Found %d secrets in %s",
		len(result.DetectedSecrets), data.URL)

	// Save results to file if enabled and secrets were found
	if len(result.DetectedSecrets) > 0 {
		if err := saveResultsToFile(result); err != nil {
			log.Printf("Error saving results to file: %v", err)
		}
	}

	// Store result in the cache
	resultsMutex.Lock()
	resultsCache[data.URL] = result
	resultsMutex.Unlock()

	// Return the analysis result
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Analysis complete")
}

// New handler to get all cached analysis results
func handleClearAllResources(w http.ResponseWriter, r *http.Request) {
	resultsMutex.RLock()
	clear(resultsCache)
	resultsMutex.RUnlock()
	json.NewEncoder(w).Encode(fmt.Sprintf("Clear completed cache is back to : %d", len(resultsCache)))
}

// New handler to get all cached analysis results
func handleSaveAllResources(w http.ResponseWriter, r *http.Request) {
	resultsMutex.RLock()
	for _, result := range resultsCache {
		if len(result.DetectedSecrets) > 0 {
			if err := saveResultsToFile(result); err != nil {
				log.Printf("Error saving results to file: %v", err)
			}
		}
	}
	resultsMutex.RUnlock()
	json.NewEncoder(w).Encode(fmt.Sprintf("Saved to : %s", outputDir))
}

func handleGetAllResources(w http.ResponseWriter, r *http.Request) {
	// Set appropriate headers
	w.Header().Set("Content-Type", "application/json")

	resultsMutex.RLock()
	// Create a slice to hold results
	results := make([]AnalysisResult, 0, len(resultsCache))
	for _, result := range resultsCache {
		results = append(results, result)
	}
	resultsMutex.RUnlock()

	log.Printf("Returning %d results", len(results))
	// Log sample of first result if available
	if len(results) > 0 {
		sample, _ := json.MarshalIndent(results[0], "", "  ")
		log.Printf("Sample result: %s", string(sample[:min(len(sample), 300)]))
	}

	// If no results, return empty array not null
	if len(results) == 0 {
		w.Write([]byte("[]"))
		return
	}

	// Use json.NewEncoder for streaming rather than marshaling the entire response at once
	// This helps with large responses
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(results); err != nil {
		log.Printf("Error encoding results: %v", err)
		http.Error(w, "Error encoding results", http.StatusInternalServerError)
		return
	}
}
