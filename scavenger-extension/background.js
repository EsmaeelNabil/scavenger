let state = {
  isCapturing: false,
  activeTabId: null,
  resourceMap: new Map(),
  captureStartTime: null,
  backendUrl: "http://localhost:8080/api/upload"
};

// Initialize state from storage when service worker starts
chrome.storage.local.get(['webAnalyzerState'], (result) => {
  if (result.webAnalyzerState) {
    try {
      const savedState = JSON.parse(result.webAnalyzerState);
      // Only restore certain properties that make sense to persist
      state.backendUrl = savedState.backendUrl || state.backendUrl;
    } catch (e) {
      console.error('Failed to parse saved state:', e);
    }
  }
});

// Save state periodically
function saveState() {
  // Only save properties that make sense to persist
  const stateToSave = {
    backendUrl: state.backendUrl
    // Don't save isCapturing, activeTabId, or resource data
  };

  chrome.storage.local.set({
    webAnalyzerState: JSON.stringify(stateToSave)
  });
}

// Track the active tab
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  state.activeTabId = activeInfo.tabId;

  if (state.isCapturing) {
    const tab = await chrome.tabs.get(state.activeTabId);
    initTabData(state.activeTabId, tab);
  }
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (state.isCapturing && changeInfo.status === 'complete' && tabId === state.activeTabId) {
    initTabData(tabId, tab);

    // Inject content script
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      files: ['content-script.js']
    }).catch(error => {
      console.error('Error injecting content script:', error);
    });
  }
});

// Create base data structure for a tab
function initTabData(tabId, tab) {
  if (!state.resourceMap.has(tabId)) {
    state.resourceMap.set(tabId, {
      tabId,
      url: tab.url,
      title: tab.title || 'Unknown',
      timestamp: Date.now(),
      resources: [],
      contentData: null,
      captureStartTime: Date.now()
    });
  } else {
    // Update existing data
    const tabData = state.resourceMap.get(tabId);
    tabData.url = tab.url;
    tabData.title = tab.title || 'Unknown';
  }
}

// Start capturing resources
async function startCapture() {
  state.isCapturing = true;
  state.captureStartTime = Date.now();
  state.resourceMap.clear();

  // Get current active tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0) {
      state.activeTabId = tabs[0].id;
      initTabData(state.activeTabId, tabs[0]);

      // Inject content script
      await chrome.scripting.executeScript({
        target: { tabId: state.activeTabId },
        files: ['content-script.js']
      });
    }
  } catch (error) {
    console.error('Error starting capture:', error);
    state.isCapturing = false;
    return { success: false, error: error.message };
  }

  return { success: true };
}

// Stop capturing resources
function stopCapture() {
  state.isCapturing = false;
  return { success: true };
}

// Handle web request capture
chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (!state.isCapturing || details.tabId === -1 || details.tabId !== state.activeTabId) return;

    try {
      // Get tab data
      if (!state.resourceMap.has(details.tabId)) {
        const tab = await chrome.tabs.get(details.tabId);
        initTabData(details.tabId, tab);
      }

      const tabData = state.resourceMap.get(details.tabId);

      // Get content type from headers
      let contentType = '';
      if (details.responseHeaders) {
        const contentTypeHeader = details.responseHeaders.find(
          header => header.name.toLowerCase() === 'content-type'
        );
        contentType = contentTypeHeader?.value || '';
      }

      // Create resource entry
      const resource = {
        url: details.url,
        type: details.type,
        contentType: contentType,
        method: details.method,
        statusCode: details.statusCode,
        fromCache: details.fromCache,
        timestamp: details.timeStamp,
        size: details.responseSize || -1,
        content: null
      };

      // Add to resources list
      tabData.resources.push(resource);

      // Fetch content for relevant resources
      if (shouldFetchContent(contentType)) {
        try {
          await fetchResourceContent(resource);
        } catch (error) {
          console.error(`Error fetching content for ${resource.url}:`, error);
          resource.error = error.message;
        }
      }
    } catch (error) {
      console.error('Error processing web request:', error);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Determine if we should fetch the content of this resource
function shouldFetchContent(contentType) {
  // Skip binary and media content
  const skipTypes = [
    'image/',
    'font/',
    'audio/',
    'video/',
    'application/octet-stream',
    'application/pdf'
  ];

  // Check if content type starts with any skip types
  for (const type of skipTypes) {
    if (contentType.startsWith(type)) return false;
  }

  return true;
}

// Fetch the actual content of a resource
async function fetchResourceContent(resource) {
  try {
    const response = await fetch(resource.url);

    // Check if this is a redirect
    if (response.redirected) {
      resource.redirectedTo = response.url;
    }

    // Only try to get text content for text resources
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('text') ||
      contentType.includes('javascript') ||
      contentType.includes('json') ||
      contentType.includes('xml') ||
      contentType.includes('html') ||
      contentType.includes('css')) {

      // Use a timeout for large resources
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Content fetch timeout')), 5000);
      });

      const textPromise = response.text();
      const text = await Promise.race([textPromise, timeoutPromise]);

      // Limit content size (in case of very large resources)
      const maxSize = 500 * 1024; // 500 KB
      resource.content = text.length > maxSize ? text.substring(0, maxSize) + '...[truncated]' : text;
    }
  } catch (error) {
    console.error(`Failed to fetch ${resource.url}:`, error);
    resource.error = error.message;
    throw error; // Re-throw to be handled by caller
  }
}

// Retrieve cookies for the current tab
async function getCookies(url) {
  try {
    // Extract domain from URL for cookie lookup
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    return await chrome.cookies.getAll({ domain });
  } catch (error) {
    console.error('Error getting cookies:', error);
    return [];
  }
}

// Send all collected data to backend
async function sendToBackend() {
  if (!state.activeTabId) {
    return { success: false, error: "No active tab" };
  }

  const tabData = state.resourceMap.get(state.activeTabId);
  if (!tabData) {
    return { success: false, error: "No data collected" };
  }

  try {
    // Get cookies
    const cookies = await getCookies(tabData.url);
    // Convert all values to strings
    const stringifiedCookies = cookies.map(cookie => {
      const result = {};
      for (const [key, value] of Object.entries(cookie)) {
        result[key] = String(value);
      }
      return result;
    });
    // Prepare payload with all collected data
    const payload = {
      url: tabData.url,
      title: tabData.title,
      timestamp: tabData.timestamp,
      resources: tabData.resources,
      contentData: tabData.contentData,
      cookies: stringifiedCookies,
      captureTime: Date.now() - tabData.captureStartTime
    };

    // Send to backend
    const response = await fetch(state.backendUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Backend server error: ${response.status}`);
    }

    const result = await response.json();
    return { success: true, result };
  } catch (error) {
    console.error('Error sending data to backend:', error);
    return { success: false, error: error.message };
  }
}

// Message handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const handleMessageAsync = async () => {
    try {
      switch (request.action) {
        case 'startCapture':
          return await startCapture();

        case 'stopCapture':
          return stopCapture();

        case 'getStatus':
          return {
            isCapturing: state.isCapturing,
            resourceCount: state.activeTabId ?
              (state.resourceMap.get(state.activeTabId)?.resources.length || 0) : 0,
            startTime: state.captureStartTime
          };

        case 'sendToBackend':
          return await sendToBackend();

        case 'contentData':
          if (state.isCapturing && sender.tab && sender.tab.id === state.activeTabId) {
            const tabData = state.resourceMap.get(state.activeTabId);
            if (tabData) {
              tabData.contentData = request.data;
              return { success: true };
            }
          }
          return { success: false, error: "Not currently capturing" };

        case 'updateSettings':
          // Update extension settings
          if (request.backendUrl) {
            state.backendUrl = request.backendUrl;
            saveState();
          }
          return { success: true };

        default:
          return { success: false, error: "Unknown action" };
      }
    } catch (error) {
      console.error(`Error handling message (${request.action}):`, error);
      return { success: false, error: error.message };
    }
  };

  // Handle asynchronous responses
  handleMessageAsync().then(sendResponse);
  return true; // Indicates async response
});
