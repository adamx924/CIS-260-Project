
  // This script runs in the context of web pages
  // Listen for messages from the background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'showWarning') {
      showPhishingWarning(message.result);
    }
  });
  
  // Function to show a warning banner
  function showPhishingWarning(result) {
    // Create warning element
    const warningDiv = document.createElement('div');
    warningDiv.style.position = 'fixed';
    warningDiv.style.top = '0';
    warningDiv.style.left = '0';
    warningDiv.style.width = '100%';
    warningDiv.style.backgroundColor = '#dc3545';
    warningDiv.style.color = 'white';
    warningDiv.style.padding = '15px';
    warningDiv.style.textAlign = 'center';
    warningDiv.style.fontWeight = 'bold';
    warningDiv.style.zIndex = '9999';
    warningDiv.style.display = 'flex';
    warningDiv.style.justifyContent = 'space-between';
    warningDiv.style.alignItems = 'center';
    
    // Add warning text
    const warningText = document.createElement('div');
    warningText.innerHTML = `
      <strong>⚠️ WARNING: Potential Phishing Website Detected!</strong> 
      <span style="margin-left: 10px;">${result.explanation}</span>
    `;
    warningDiv.appendChild(warningText);
    
    // Add close button
    const closeButton = document.createElement('button');
    closeButton.textContent = '✖';
    closeButton.style.background = 'none';
    closeButton.style.border = 'none';
    closeButton.style.color = 'white';
    closeButton.style.fontSize = '20px';
    closeButton.style.cursor = 'pointer';
    closeButton.onclick = () => {
      document.body.removeChild(warningDiv);
    };
    warningDiv.appendChild(closeButton);
    
    // Add to the document
    document.body.prepend(warningDiv);
  }
  