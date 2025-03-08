(function () {
  // Check if the script has already run on this page
  if (window.__webResourceAnalyzerRun) return;
  window.__webResourceAnalyzerRun = true;

  // Function to extract localStorage data
  function getLocalStorage() {
    try {
      const storage = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        try {
          storage[key] = localStorage.getItem(key);
        } catch (e) {
          storage[key] = `[Error reading value: ${e.message}]`;
        }
      }
      return storage;
    } catch (e) {
      console.error('Error accessing localStorage:', e);
      return { error: e.message };
    }
  }

  // Function to extract sessionStorage data
  function getSessionStorage() {
    try {
      const storage = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        try {
          storage[key] = sessionStorage.getItem(key);
        } catch (e) {
          storage[key] = `[Error reading value: ${e.message}]`;
        }
      }
      return storage;
    } catch (e) {
      console.error('Error accessing sessionStorage:', e);
      return { error: e.message };
    }
  }

  // Function to get inline scripts
  function getInlineScripts() {
    try {
      return Array.from(document.querySelectorAll('script:not([src])')).map(script => ({
        content: script.textContent,
        type: script.getAttribute('type') || 'text/javascript'
      }));
    } catch (e) {
      console.error('Error extracting inline scripts:', e);
      return [];
    }
  }

  // Function to get inline styles
  function getInlineStyles() {
    try {
      return Array.from(document.querySelectorAll('style')).map(style => ({
        content: style.textContent,
        type: style.getAttribute('type') || 'text/css'
      }));
    } catch (e) {
      console.error('Error extracting inline styles:', e);
      return [];
    }
  }

  // Get basic DOM information (with size limits to avoid excessive data)
  function getBasicDOM() {
    try {
      // Count elements (with reasonable limit)
      const elementCounts = {};
      const maxElements = 10000; // Avoid counting forever on huge pages
      let elementCount = 0;

      try {
        // Using a more efficient approach to count elements
        const elements = document.querySelectorAll('*');
        elements.forEach(element => {
          if (elementCount++ < maxElements) {
            const tagName = element.tagName.toLowerCase();
            elementCounts[tagName] = (elementCounts[tagName] || 0) + 1;
          }
        });
      } catch (e) {
        console.error('Error counting elements:', e);
      }

      // Safely get body text with limit
      let bodyText = '';
      try {
        bodyText = document.body ? document.body.innerText.slice(0, 20000) : '';
      } catch (e) {
        console.error('Error getting body text:', e);
      }

      // Get meta tags
      const metaTags = [];
      try {
        document.querySelectorAll('meta').forEach(meta => {
          metaTags.push({
            name: meta.getAttribute('name'),
            content: meta.getAttribute('content'),
            property: meta.getAttribute('property')
          });
        });
      } catch (e) {
        console.error('Error getting meta tags:', e);
      }

      return {
        title: document.title || '',
        url: window.location.href,
        elementCounts: elementCounts,
        totalElements: Math.min(elementCount, maxElements),
        bodyText: bodyText,
        metaTags: metaTags
      };
    } catch (e) {
      console.error('Error getting DOM information:', e);
      return { error: e.message };
    }
  }

  // Function to get performance data
  function getPerformanceData() {
    try {
      if (!window.performance) {
        return { available: false };
      }

      // Get navigation timing data
      let navigationTiming = {};
      try {
        const navEntry = performance.getEntriesByType('navigation')[0];
        if (navEntry) {
          navigationTiming = {
            domContentLoaded: navEntry.domContentLoadedEventEnd - navEntry.startTime,
            load: navEntry.loadEventEnd - navEntry.startTime,
            domInteractive: navEntry.domInteractive - navEntry.startTime,
            firstByte: navEntry.responseStart - navEntry.requestStart,
            dns: navEntry.domainLookupEnd - navEntry.domainLookupStart,
            connect: navEntry.connectEnd - navEntry.connectStart,
            request: navEntry.responseStart - navEntry.requestStart,
            response: navEntry.responseEnd - navEntry.responseStart
          };
        }
      } catch (e) {
        console.error('Error getting navigation timing:', e);
      }

      // Get resource timing data (limited to avoid excessive data)
      const resourceTimings = [];
      try {
        const entries = performance.getEntriesByType('resource');
        const maxEntries = 100; // Limit number of entries

        for (let i = 0; i < Math.min(entries.length, maxEntries); i++) {
          const entry = entries[i];
          resourceTimings.push({
            name: entry.name,
            duration: entry.duration,
            initiatorType: entry.initiatorType,
            size: entry.transferSize || 0
          });
        }
      } catch (e) {
        console.error('Error getting resource timing:', e);
      }

      return {
        available: true,
        navigation: navigationTiming,
        resources: resourceTimings
      };
    } catch (e) {
      console.error('Error getting performance data:', e);
      return { error: e.message };
    }
  }

  // Collect security-related information
  function getSecurityInfo() {
    try {
      return {
        isSecure: window.location.protocol === 'https:',
        hasMixedContent: document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]').length > 0,
        contentSecurityPolicy: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute('content') || null
      };
    } catch (e) {
      console.error('Error getting security info:', e);
      return { error: e.message };
    }
  }

  // Collect all data
  try {
    const collectedData = {
      localStorage: getLocalStorage(),
      sessionStorage: getSessionStorage(),
      inlineScripts: getInlineScripts(),
      inlineStyles: getInlineStyles(),
      dom: getBasicDOM(),
      performance: getPerformanceData(),
      security: getSecurityInfo(),
      timestamp: Date.now()
    };

    // Send data back to background script
    chrome.runtime.sendMessage({
      action: "contentData",
      data: collectedData
    }).catch(error => {
      console.error('Error sending content data to background script:', error);
    });
  } catch (e) {
    console.error('Error collecting page data:', e);
    chrome.runtime.sendMessage({
      action: "contentData",
      data: { error: e.message }
    }).catch(error => {
      console.error('Error sending error to background script:', error);
    });
  }
})();
