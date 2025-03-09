package main

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

type SecurityIssue struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
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

