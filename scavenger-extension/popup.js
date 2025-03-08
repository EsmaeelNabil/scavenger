document.addEventListener('DOMContentLoaded', async () => {
  // UI Elements
  const startBtn = document.getElementById('start-btn');
  const stopBtn = document.getElementById('stop-btn');
  const sendBtn = document.getElementById('send-btn');
  const statusEl = document.getElementById('status');
  const resourceCountEl = document.getElementById('resource-count');
  const backendUrlInput = document.getElementById('backend-url');
  const saveSettingsBtn = document.getElementById('save-settings-btn');
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');

  let isCapturing = false;
  let captureInterval = null;

  // Tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Deactivate all tabs
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      // Activate clicked tab
      tab.classList.add('active');
      document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
    });
  });

  // Load settings
  try {
    const result = await chrome.runtime.sendMessage({ action: 'getStatus' });
    isCapturing = result.isCapturing;
    updateUI();

    if (result.isCapturing) {
      startResourceCountUpdater();
    }

    // Load backend URL setting
    const settings = await chrome.storage.local.get(['webAnalyzerState']);
    if (settings.webAnalyzerState) {
      try {
        const state = JSON.parse(settings.webAnalyzerState);
        if (state.backendUrl) {
          backendUrlInput.value = state.backendUrl;
        }
      } catch (e) {
        console.error('Error parsing settings:', e);
      }
    }
  } catch (error) {
    console.error('Error loading initial state:', error);
    showError('Error connecting to extension. Please reload the extension.');
  }

  // Start capturing
  startBtn.addEventListener('click', async () => {
    try {
      startBtn.disabled = true;
      statusEl.className = 'status';
      statusEl.innerHTML = '<div class="spinner"></div> Starting capture...';

      const result = await chrome.runtime.sendMessage({ action: 'startCapture' });

      if (result.success) {
        isCapturing = true;
        statusEl.className = 'status success';
        statusEl.textContent = 'Capturing resources...';
        startResourceCountUpdater();
      } else {
        showError(`Failed to start: ${result.error}`);
      }
    } catch (error) {
      showError(`Error: ${error.message}`);
    } finally {
      updateUI();
    }
  });

  // Stop capturing
  stopBtn.addEventListener('click', async () => {
    try {
      stopBtn.disabled = true;

      const result = await chrome.runtime.sendMessage({ action: 'stopCapture' });

      if (result.success) {
        isCapturing = false;
        statusEl.className = 'status';
        statusEl.textContent = 'Capture stopped';
        stopResourceCountUpdater();
      } else {
        showError(`Failed to stop: ${result.error}`);
      }
    } catch (error) {
      showError(`Error: ${error.message}`);
    } finally {
      updateUI();
    }
  });

  // Send to backend
  sendBtn.addEventListener('click', async () => {
    try {
      sendBtn.disabled = true;
      statusEl.className = 'status';
      statusEl.innerHTML = '<div class="spinner"></div> Sending data to backend...';

      const result = await chrome.runtime.sendMessage({ action: 'sendToBackend' });

      if (result.success) {
        statusEl.className = 'status success';
        statusEl.textContent = 'Data sent successfully!';
      } else {
        showError(`Failed to send: ${result.error}`);
      }
    } catch (error) {
      showError(`Error: ${error.message}`);
    } finally {
      sendBtn.disabled = !isCapturing;
    }
  });

  // Save settings
  saveSettingsBtn.addEventListener('click', async () => {
    try {
      const backendUrl = backendUrlInput.value.trim();

      if (backendUrl) {
        await chrome.runtime.sendMessage({
          action: 'updateSettings',
          backendUrl
        });

        statusEl.className = 'status success';
        statusEl.textContent = 'Settings saved successfully!';
      } else {
        showError('Backend URL cannot be empty');
      }
    } catch (error) {
      showError(`Error saving settings: ${error.message}`);
    }
  });

  // Update resource count periodically
  function startResourceCountUpdater() {
    stopResourceCountUpdater();

    updateResourceCount();
    captureInterval = setInterval(updateResourceCount, 1000);
  }

  function stopResourceCountUpdater() {
    if (captureInterval) {
      clearInterval(captureInterval);
      captureInterval = null;
    }
  }

  async function updateResourceCount() {
    try {
      const result = await chrome.runtime.sendMessage({ action: 'getStatus' });

      if (result.isCapturing) {
        const count = result.resourceCount || 0;
        const startTime = result.startTime || Date.now();
        const elapsedSeconds = Math.floor((Date.now() - startTime) / 1000);

        resourceCountEl.textContent = `Captured ${count} resources (${formatTime(elapsedSeconds)})`;
      } else {
        stopResourceCountUpdater();
      }
    } catch (error) {
      console.error('Error updating resource count:', error);
    }
  }

  // Format seconds into MM:SS
  function formatTime(seconds) {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  }

  // Show error message
  function showError(message) {
    statusEl.className = 'status error';
    statusEl.textContent = message;
  }

  // Update UI based on current state
  function updateUI() {
    startBtn.disabled = isCapturing;
    stopBtn.disabled = !isCapturing;
    sendBtn.disabled = !isCapturing;

    if (!isCapturing) {
      resourceCountEl.textContent = 'No data being captured';
    }
  }
});
