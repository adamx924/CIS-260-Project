// 
// This script runs when the popup is opened
document.addEventListener('DOMContentLoaded', async () => {
    const loadingElement = document.getElementById('loading');
    const resultElement = document.getElementById('result');
    const analyzeBtn = document.getElementById('analyze-btn');
    const serverUrlInput = document.getElementById('server-url');
    const saveSettingsBtn = document.getElementById('save-settings-btn');
    
    // Get server URL from background script
    chrome.runtime.sendMessage({action: 'getServerUrl'}, (response) => {
      serverUrlInput.value = response.url;
    });
    
    // Get current tab URL
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const url = tab.url;
    
    // Check if we've already analyzed this URL
    const analyzeResult = await getAnalysisResult(url);
    
    if (analyzeResult) {
      displayResult(analyzeResult);
    } else {
      // Analyze current page
      analyzeCurrentPage();
    }
    
    // Analyze button click
    analyzeBtn.addEventListener('click', () => {
      analyzeCurrentPage();
    });
    
    // Save settings button click
    saveSettingsBtn.addEventListener('click', () => {
      const newServerUrl = serverUrlInput.value.trim();
      
      if (!newServerUrl) {
        showMessage('Please enter a valid server URL');
        return;
      }
      
      chrome.runtime.sendMessage({
        action: 'setServerUrl',
        url: newServerUrl
      }, (response) => {
        if (response.success) {
          showMessage('Settings saved successfully', 'safe');
        } else {
          showMessage('Failed to save settings');
        }
      });
    });
    
    // Function to analyze the current page
    async function analyzeCurrentPage() {
      showLoading();
      
      try {
        // Get current tab URL
        const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
        const url = tab.url;
        
        // Send message to background script
        const formData = new FormData();
        formData.append('url', url);
        
        // Get server URL
        const serverUrl = await getServerUrl();
        
        const response = await fetch(`${serverUrl}/analyze_url`, {
          method: 'POST',
          body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
          // Store the result
          storeResult(url, data.result);
          
          // Display the result
          displayResult(data.result);
        } else {
          throw new Error(data.error || 'Failed to analyze URL');
        }
      } catch (error) {
        showError(error.message);
      }
    }
    
    // Function to display the analysis result
    function displayResult(result) {
      hideLoading();
      
      // Determine result class
      let resultClass = 'safe';
      let resultIcon = '✅';
      let resultTitle = 'Safe';
      
      if (result.is_phishing) {
        resultClass = 'dangerous';
        resultIcon = '⚠️';
        resultTitle = 'Phishing Detected';
      } else if (result.confidence > 0.4) {
        resultClass = 'suspicious';
        resultIcon = '⚠️';
        resultTitle = 'Suspicious';
      }
      
      // Set result content
      resultElement.className = `result ${resultClass}`;
      resultElement.innerHTML = `
        <p><strong>${resultIcon} ${resultTitle}</strong></p>
        <p>${result.explanation}</p>
        <p>Confidence: ${(result.confidence * 100).toFixed(1)}%</p>
      `;
      
      resultElement.style.display = 'block';
    }
    
    // Functions to show/hide loading state
    function showLoading() {
      loadingElement.style.display = 'block';
      resultElement.style.display = 'none';
    }
    
    function hideLoading() {
      loadingElement.style.display = 'none';
    }
    
    // Function to show error message
    function showError(message) {
      hideLoading();
      
      resultElement.className = 'result dangerous';
      resultElement.innerHTML = `
        <p><strong>⚠️ Error</strong></p>
        <p>${message}</p>
      `;
      
      resultElement.style.display = 'block';
    }
    
    // Function to show a message
    function showMessage(message, type = 'dangerous') {
      resultElement.className = `result ${type}`;
      resultElement.innerHTML = `<p>${message}</p>`;
      resultElement.style.display = 'block';
    }
    
    // Helper functions to interact with storage
    async function getAnalysisResult(url) {
      const data = await chrome.storage.local.get('analyzedUrls');
      const analyzedUrls = data.analyzedUrls || {};
      
      return analyzedUrls[url];
    }
    
    async function storeResult(url, result) {
      // Get existing results
      const data = await chrome.storage.local.get('analyzedUrls');
      const analyzedUrls = data.analyzedUrls || {};
      
      // Add new result
      analyzedUrls[url] = {
        is_phishing: result.is_phishing,
        confidence: result.confidence,
        explanation: result.explanation,
        timestamp: Date.now()
      };
      
      // Store updated results
      await chrome.storage.local.set({analyzedUrls});
    }
    
    async function getServerUrl() {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({action: 'getServerUrl'}, (response) => {
          resolve(response.url);
        });
      });
    }
  });