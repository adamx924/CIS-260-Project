let serverUrl = 'http://localhost:5000';
  
  // Listen for navigation events
  chrome.webNavigation.onCompleted.addListener(async (details) => {
    // Only check the main frame
    if (details.frameId !== 0) return;
    
    // Get the URL
    const url = details.url;
    
    // Check if the URL is valid
    if (!url || url.startsWith('chrome://')) return;
    
    // Check if we've already analyzed this URL
    const storedResult = await getStoredResult(url);
    if (storedResult) {
      // URL has been analyzed before
      updateIcon(storedResult.is_phishing);
      return;
    }
    
    // Analyze the URL
    try {
      const result = await analyzeUrl(url);
      
      // Store the result
      storeResult(url, result);
      
      // Update the extension icon
      updateIcon(result.is_phishing);
      
      // If it's a phishing site, show a warning
      if (result.is_phishing && result.confidence > 0.7) {
        // Send message to content script to show a warning
        chrome.tabs.query({active: true, currentWindow: true}, tabs => {
          chrome.tabs.sendMessage(tabs[0].id, {
            action: "showWarning",
            result: result
          });
        });
      }
    } catch (error) {
      console.error('Error analyzing URL:', error);
    }
  });
  
  // Function to analyze URL
  async function analyzeUrl(url) {
    const formData = new FormData();
    formData.append('url', url);
    
    const response = await fetch(`${serverUrl}/analyze_url`, {
      method: 'POST',
      body: formData
    });
    
    const data = await response.json();
    
    if (!data.success) {
      throw new Error(data.error || 'Failed to analyze URL');
    }
    
    return data.result;
  }
  
  // Function to update the extension icon
  function updateIcon(isPhishing) {
    // Set icon based on phishing status
    const iconPath = isPhishing ? 'images/icon_danger.png' : 'images/icon.png';
    
    chrome.action.setIcon({
      path: {
        16: iconPath,
        48: iconPath,
        128: iconPath
      }
    });
  }
  
  // Function to store result in local storage
  async function storeResult(url, result) {
    // Get existing results
    const data = await chrome.storage.local.get('analyzedUrls');
    const analyzedUrls = data.analyzedUrls || {};
    
    // Add new result (keeping only necessary information to save space)
    analyzedUrls[url] = {
      is_phishing: result.is_phishing,
      confidence: result.confidence,
      explanation: result.explanation,
      timestamp: Date.now()
    };
    
    // Store updated results
    await chrome.storage.local.set({analyzedUrls});
  }
  
  // Function to get stored result
  async function getStoredResult(url) {
    const data = await chrome.storage.local.get('analyzedUrls');
    const analyzedUrls = data.analyzedUrls || {};
    
    const result = analyzedUrls[url];
    
    // Only return if result is recent (less than 1 day old)
    if (result && Date.now() - result.timestamp < 24 * 60 * 60 * 1000) {
      return result;
    }
    
    return null;
  }
  
  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getServerUrl') {
      sendResponse({url: serverUrl});
    } else if (message.action === 'setServerUrl') {
      serverUrl = message.url;
      chrome.storage.local.set({serverUrl});
      sendResponse({success: true});
    }
    
    return true;
  });
  
  // Initialize server URL from storage
  chrome.storage.local.get('serverUrl', (data) => {
    if (data.serverUrl) {
      serverUrl = data.serverUrl;
    }
  });
  