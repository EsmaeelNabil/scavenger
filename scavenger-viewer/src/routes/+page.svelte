<script lang="ts">
    import {onMount} from 'svelte';
    import type {AnalysisResult, DetectedSecret} from "$lib/types/analysis";
    import {goto} from "$app/navigation";

    // State variables
    let analysisResults: AnalysisResult[] = [];
    let loading = true;
    let error: string | null = null;
    let expandedResult: string | null = null;
    let expandedSecretTypes: Set<string> = new Set();

    // Fetch data from API
    async function saveResults() {
        loading = true;
        error = null;

        try {
            const response = await fetch('http://localhost:8080/api/save');

            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }

        } catch (err) {
            error = err instanceof Error ? err.message : 'Unknown error occurred';
            console.error('Error fetching data:', err);
        } finally {
            loading = false;
        }
    }

    // Fetch data from API
    async function clearResults() {
        loading = true;
        error = null;

        try {
            const response = await fetch('http://localhost:8080/api/clear', {
                method: 'DELETE',
            });

            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }

            await goto("/");
        } catch (err) {
            error = err instanceof Error ? err.message : 'Unknown error occurred';
            console.error('Error fetching data:', err);
        } finally {
            loading = false;
        }
    }

    // Fetch data from API
    async function fetchAnalysisResults() {
        loading = true;
        error = null;

        try {
            const response = await fetch('http://localhost:8080/api/resources');

            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }

            analysisResults = await response.json();
        } catch (err) {
            error = err instanceof Error ? err.message : 'Unknown error occurred';
            console.error('Error fetching data:', err);
        } finally {
            loading = false;
        }
    }

    // Format date
    function formatDate(dateString: string): string {
        return new Date(dateString).toLocaleString();
    }

    // Toggle expanded view for results
    function toggleExpand(url: string) {
        expandedResult = expandedResult === url ? null : url;
    }

    // Toggle expanded view for secret types
    function toggleSecretType(secretType: string) {
        if (expandedSecretTypes.has(secretType)) {
            expandedSecretTypes.delete(secretType);
        } else {
            expandedSecretTypes.add(secretType);
        }
        expandedSecretTypes = expandedSecretTypes; // Trigger reactivity
    }

    // Get severity color
    function getSeverityColor(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'high':
                return 'bg-red-500';
            case 'medium':
                return 'bg-yellow-500';
            case 'low':
                return 'bg-green-500';
            default:
                return 'bg-gray-500';
        }
    }

    // Get confidence color
    function getConfidenceColor(confidence: string): string {
        switch (confidence.toLowerCase()) {
            case 'high':
                return 'bg-red-500';
            case 'medium':
                return 'bg-yellow-500';
            case 'low':
                return 'bg-green-500';
            default:
                return 'bg-gray-500';
        }
    }

    // Group secrets by type
    function groupSecretsByType(secrets: DetectedSecret[]): Record<string, DetectedSecret[]> {
        const grouped: Record<string, DetectedSecret[]> = {};

        if (!secrets || !Array.isArray(secrets)) {
            return {};
        }

        secrets.forEach(secret => {
            const type = secret.type || 'Unknown';
            if (!grouped[type]) {
                grouped[type] = [];
            }
            grouped[type].push(secret);
        });

        return grouped;
    }

    // Load data on mount
    onMount(() => {
        fetchAnalysisResults();
    });
</script>

<main class="max-w-6xl mx-auto p-4 font-sans">
    <h1 class="text-2xl font-bold text-gray-800 mb-4">Website Analysis Results</h1>

    <button
            class="bg-green-500 hover:bg-green-600 text-white font-medium py-2 px-4 rounded mb-6 transition-colors duration-200"
            on:click={fetchAnalysisResults}
    >
        Refresh Data
    </button>

    <button
            class="bg-red-500 hover:bg-yellow-200 text-white font-medium py-2 px-4 rounded mb-6 transition-colors duration-200"
            on:click={clearResults}
    >
        Clear Data
    </button>

    <button
            class="bg-green-500 hover:bg-green-600 text-white font-medium py-2 px-4 rounded mb-6 transition-colors duration-200"
            on:click={saveResults}
    >
        Save Results to filesystem
    </button>

    {#if loading}
        <div class="bg-gray-100 text-gray-600 p-4 rounded text-center">Loading analysis results...</div>
    {:else if error}
        <div class="bg-red-100 text-red-800 p-4 rounded text-center">
            <p class="mb-2">Error: {error}</p>
            <button
                    class="bg-red-500 hover:bg-red-600 text-white font-medium py-1 px-3 rounded"
                    on:click={fetchAnalysisResults}
            >
                Try Again
            </button>
        </div>
    {:else if analysisResults.length === 0}
        <div class="bg-gray-100 text-gray-600 p-4 rounded text-center">No analysis results found</div>
    {:else}
        <div class="flex flex-col gap-5">
            {#each analysisResults as result}
                <div class="border border-gray-200 rounded-lg shadow-sm overflow-hidden">
                    <div
                            class="p-4 bg-gray-50 cursor-pointer hover:bg-gray-100 transition-colors duration-200 relative"
                            on:click={() => toggleExpand(result.url)}
                    >
                        <h2 class="text-lg font-semibold text-gray-800 mb-2">{result.title || result.url}</h2>
                        <div class="flex flex-col gap-1 text-sm text-gray-600">
                            <span class="truncate">{result.url}</span>
                            <span>Analyzed: {formatDate(result.analysisTimestamp)}</span>
                        </div>
                        <div class="absolute right-5 top-1/2 transform -translate-y-1/2 text-gray-500">
                            {expandedResult === result.url ? '▼' : '▶'}
                        </div>
                    </div>

                    {#if expandedResult === result.url}
                        <div class="p-4 bg-white">
                            <div class="mb-6">
                                <h3 class="text-md font-semibold text-gray-700 pb-2 border-b border-gray-200 mb-3">
                                    Resource Stats</h3>
                                <div class="grid grid-cols-3 gap-2 md:grid-cols-3 sm:grid-cols-2">
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">Total</span>
                                        <span>{result.resourceStats.totalResources}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">HTML</span>
                                        <span>{result.resourceStats.htmlCount}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">JavaScript</span>
                                        <span>{result.resourceStats.jsCount}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">CSS</span>
                                        <span>{result.resourceStats.cssCount}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">JSON</span>
                                        <span>{result.resourceStats.jsonCount}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">XML</span>
                                        <span>{result.resourceStats.xmlCount}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">Fonts</span>
                                        <span>{result.resourceStats.fontCount}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">Images</span>
                                        <span>{result.resourceStats.imageCount}</span>
                                    </div>
                                    <div class="bg-gray-50 p-2 rounded flex justify-between">
                                        <span class="font-medium text-gray-700">Other</span>
                                        <span>{result.resourceStats.otherCount}</span>
                                    </div>
                                </div>
                            </div>

                            {#if result.securityIssues && result.securityIssues.length > 0}
                                <div class="mb-6">
                                    <h3 class="text-md font-semibold text-gray-700 pb-2 border-b border-gray-200 mb-3">
                                        Security Issues ({result.securityIssues.length})
                                    </h3>
                                    <div class="flex flex-col gap-3">
                                        {#each result.securityIssues as issue}
                                            <div class="bg-gray-50 p-3 rounded border-l-4 border-gray-400">
                                                <div class="flex justify-between mb-2">
                                                    <span class="font-semibold text-gray-800">{issue.type}</span>
                                                    <span class={`${getSeverityColor(issue.severity)} text-white text-xs px-2 py-1 rounded-full`}>
                                                        {issue.severity}
                                                    </span>
                                                </div>
                                                <div class="mb-2">{issue.description}</div>
                                                <div class="text-sm text-gray-600">Source: {issue.source}</div>
                                            </div>
                                        {/each}
                                    </div>
                                </div>
                            {/if}

                            {#if result.detectedSecrets && result.detectedSecrets.length > 0}
                                <div class="mb-6">
                                    <h3 class="text-md font-semibold text-gray-700 pb-2 border-b border-gray-200 mb-3">
                                        Detected Secrets ({result.detectedSecrets.length})
                                    </h3>

                                    {#each Object.entries(groupSecretsByType(result.detectedSecrets)) as [secretType, secrets]}
                                        <div class="mb-4">
                                            <div
                                                    class="font-medium text-gray-800 bg-gray-100 p-2 rounded flex justify-between items-center cursor-pointer hover:bg-gray-200"
                                                    on:click={() => toggleSecretType(secretType)}
                                            >
                                                <div class="flex items-center">
                                                    <span class="mr-2 text-gray-500">
                                                        {expandedSecretTypes.has(secretType) ? '▼' : '▶'}
                                                    </span>
                                                    <span>{secretType} ({secrets.length})</span>
                                                </div>
                                            </div>

                                            {#if expandedSecretTypes.has(secretType)}
                                                <div class="flex flex-col gap-3 pl-2 mt-2">
                                                    {#each secrets as secret}
                                                        <div class="bg-gray-50 p-3 rounded border-l-4 border-gray-400">
                                                            <div class="flex justify-between mb-2">
                                                                <span class="font-semibold text-gray-800">{secret.type}</span>
                                                                <span class={`${getConfidenceColor(secret.confidence)} text-white text-xs px-2 py-1 rounded-full`}>
                                                                    {secret.confidence}
                                                                </span>
                                                            </div>
                                                            <div class="break-all mb-2">
                                                                <span class="font-medium">Value: </span>
                                                                {secret.value}
                                                            </div>
                                                            <div class="text-sm text-gray-600 mb-1">
                                                                <span class="font-medium">Resource: </span>
                                                                {secret.resourceUrl}
                                                            </div>
                                                            <div class="text-sm text-gray-600">
                                                                <span class="font-medium">Context: </span>
                                                                {secret.context}
                                                            </div>
                                                        </div>
                                                    {/each}
                                                </div>
                                            {/if}
                                        </div>
                                    {/each}
                                </div>
                            {/if}

                            <div class="mb-6">
                                <h3 class="text-md font-semibold text-gray-700 pb-2 border-b border-gray-200 mb-3">
                                    Domains</h3>
                                <div class="flex flex-col gap-1">
                                    {#each Object.entries(result.domains) as [domain, count]}
                                        <div class="bg-gray-50 p-2 rounded flex justify-between items-center">
                                            <span class="font-medium text-gray-800">{domain}</span>
                                            <span class="bg-gray-500 text-white text-xs px-2 py-1 rounded-full">{count}</span>
                                        </div>
                                    {/each}
                                </div>
                            </div>
                        </div>
                    {/if}
                </div>
            {/each}
        </div>
    {/if}
</main>