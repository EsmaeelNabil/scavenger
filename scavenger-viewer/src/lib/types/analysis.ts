export interface SecurityIssue {
    type: string;
    description: string;
    severity: string;
    source: string;
}

export interface DetectedSecret {
    type: string;
    value: string;
    resourceUrl: string;
    context: string;
    confidence: string; // high, medium, low
}

export interface ResourceStats {
    totalResources: number;
    htmlCount: number;
    jsCount: number;
    cssCount: number;
    jsonCount: number;
    xmlCount: number;
    fontCount: number;
    imageCount: number;
    otherCount: number;
}

// The Comment interface isn't defined in the provided Go code
// This is a placeholder - replace with the actual structure
export interface Comment {
    [key: string]: any;
}

export interface AnalysisResult {
    url: string;
    title: string;
    analysisTimestamp: string;
    resourceStats: ResourceStats;
    contentTypes: Record<string, number>;
    domains: Record<string, number>;
    codeAnalysis: Record<string, Record<string, any>>;
    comments: Comment[];
    storageData: Record<string, number>;
    cookieAnalysis: Record<string, number>;
    securityIssues: SecurityIssue[];
    performanceInfo: Record<string, any>;
    detectedSecrets: DetectedSecret[];
}