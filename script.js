// static/js/script.js

document.addEventListener('DOMContentLoaded', function() {
    // URL Analysis Form
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const urlResult = document.getElementById('url-result');
    const urlStatusIcon = document.getElementById('url-status-icon');
    const urlStatusTitle = document.getElementById('url-status-title');
    const urlStatusMessage = document.getElementById('url-status-message');
    const urlDetails = document.getElementById('url-details');
    
    // Email Analysis Form
    const emailForm = document.getElementById('email-form');
    const emailInput = document.getElementById('email-input');
    const emailResult = document.getElementById('email-result');
    const emailStatusIcon = document.getElementById('email-status-icon');
    const emailStatusTitle = document.getElementById('email-status-title');
    const emailStatusMessage = document.getElementById('email-status-message');
    const emailDetails = document.getElementById('email-details');
    
    // Training Button
    const trainModelsBtn = document.getElementById('train-models-btn');
    const trainingStatus = document.getElementById('training-status');
    
    // URL Analysis Form Submission
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        if (!url) {
            showAlert(urlForm, 'Please enter a URL to analyze.');
            return;
        }
        
        // Show the result container
        urlResult.classList.remove('d-none');
        
        // Reset the status
        urlStatusIcon.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        urlStatusTitle.textContent = 'Analyzing...';
        urlStatusMessage.textContent = 'Please wait while we analyze this URL.';
        urlDetails.innerHTML = '';
        
        // Send the URL for analysis
        const formData = new FormData();
        formData.append('url', url);
        
        fetch('/analyze_url', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayUrlResult(data.result);
            } else {
                throw new Error(data.error || 'Failed to analyze URL');
            }
        })
        .catch(error => {
            urlStatusIcon.innerHTML = '<i class="fas fa-exclamation-triangle text-danger"></i>';
            urlStatusTitle.textContent = 'Error';
            urlStatusMessage.textContent = error.message;
            urlDetails.innerHTML = '';
        });
    });
    
    // Email Analysis Form Submission
    emailForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const emailContent = emailInput.value.trim();
        if (!emailContent) {
            showAlert(emailForm, 'Please enter email content to analyze.');
            return;
        }
        
        // Show the result container
        emailResult.classList.remove('d-none');
        
        // Reset the status
        emailStatusIcon.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        emailStatusTitle.textContent = 'Analyzing...';
        emailStatusMessage.textContent = 'Please wait while we analyze this email.';
        emailDetails.innerHTML = '';
        
        // Send the email for analysis
        const formData = new FormData();
        formData.append('email_content', emailContent);
        
        fetch('/analyze_email', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayEmailResult(data.result);
            } else {
                throw new Error(data.error || 'Failed to analyze email');
            }
        })
        .catch(error => {
            emailStatusIcon.innerHTML = '<i class="fas fa-exclamation-triangle text-danger"></i>';
            emailStatusTitle.textContent = 'Error';
            emailStatusMessage.textContent = error.message;
            emailDetails.innerHTML = '';
        });
    });
    
    // Train Models Button
    trainModelsBtn.addEventListener('click', function() {
        // Show loading state
        trainModelsBtn.disabled = true;
        trainModelsBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Training...';
        trainingStatus.classList.remove('d-none');
        trainingStatus.classList.add('alert-info');
        trainingStatus.innerHTML = '<i class="fas fa-info-circle me-2"></i>Training models. This may take a few minutes...';
        
        // Send the request to train models
        fetch('/train_models', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                trainingStatus.classList.remove('alert-info');
                trainingStatus.classList.add('alert-success');
                trainingStatus.innerHTML = '<i class="fas fa-check-circle me-2"></i>' + data.message;
            } else {
                throw new Error(data.error || 'Failed to train models');
            }
        })
        .catch(error => {
            trainingStatus.classList.remove('alert-info');
            trainingStatus.classList.add('alert-danger');
            trainingStatus.innerHTML = '<i class="fas fa-exclamation-circle me-2"></i>' + error.message;
        })
        .finally(() => {
            // Reset button state
            trainModelsBtn.disabled = false;
            trainModelsBtn.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Train Models';
        });
    });
    
    // Display URL Analysis Result
    function displayUrlResult(result) {
        // Update alert style and icon based on result
        const statusAlert = urlResult.querySelector('.alert');
        if (!result) {
            urlStatusIcon.innerHTML = '<i class="fas fa-exclamation-triangle text-danger"></i>';
            urlStatusTitle.textContent = 'Error';
            urlStatusMessage.textContent = 'Invalid response from server';
            statusAlert.className = 'alert d-flex align-items-center alert-danger';
            return;
        }
        
        // Add additional check for result.details
        if (!result.details) {
            urlStatusIcon.innerHTML = '<i class="fas fa-exclamation-triangle text-danger"></i>';
            urlStatusTitle.textContent = 'Error';
            urlStatusMessage.textContent = result.explanation || 'Analysis failed due to missing details';
            statusAlert.className = 'alert d-flex align-items-center alert-danger';
            return;
        }
        if (result.is_phishing === null) {
            // Unable to analyze
            urlStatusIcon.innerHTML = '<i class="fas fa-question-circle text-secondary"></i>';
            urlStatusTitle.textContent = 'Unable to Analyze';
            urlStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-secondary';
        } else if (result.is_phishing) {
            // Phishing detected
            urlStatusIcon.innerHTML = '<i class="fas fa-exclamation-triangle status-phishing"></i>';
            urlStatusTitle.textContent = 'Phishing Detected';
            urlStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-danger';
        } else if (result.confidence > 0.4) {
            // Suspicious
            urlStatusIcon.innerHTML = '<i class="fas fa-exclamation-circle status-suspicious"></i>';
            urlStatusTitle.textContent = 'Suspicious';
            urlStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-warning';
        } else {
            // Safe
            urlStatusIcon.innerHTML = '<i class="fas fa-check-circle status-safe"></i>';
            urlStatusTitle.textContent = 'Safe';
            urlStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-success';
        }
        
        // Generate detailed analysis
        let detailsHtml = `
            <div class="detail-section">
                <h5>Overview</h5>
                <div class="row mb-3">
                    <div class="col-md-6">
                        <p><strong>URL:</strong> ${result.details.url_structure_analysis.url}</p>
                        <p><strong>Domain:</strong> ${result.details.domain_analysis.domain}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Phishing Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
                        <div class="confidence-meter">
                            <div class="confidence-fill" style="width: ${result.confidence * 100}%; background-color: ${getConfidenceColor(result.confidence)};"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- URL Structure Analysis -->
            <div class="detail-section">
                <h5>URL Structure Analysis</h5>
                ${generateDetailList(result.details.url_structure_analysis.suspicious_indicators)}
            </div>
            
            <!-- Domain Analysis -->
            <div class="detail-section">
                <h5>Domain Analysis</h5>
                ${generateDetailList(result.details.domain_analysis.suspicious_indicators)}
            </div>
            
            <!-- Security Analysis -->
            <div class="detail-section">
                <h5>Security Analysis</h5>
                <p><strong>Uses HTTPS:</strong> ${result.details.security_analysis.is_https ? 'Yes' : 'No'}</p>
                ${generateDetailList(result.details.security_analysis.ssl_issues)}
            </div>
            
            <!-- Content Analysis -->
            ${result.details.content_analysis.error ? '' : `
            <div class="detail-section">
                <h5>Content Analysis</h5>
                <p><strong>Has Login Form:</strong> ${result.details.content_analysis.has_login_form ? 'Yes' : 'No'}</p>
                <p><strong>Has Password Field:</strong> ${result.details.content_analysis.has_password_field ? 'Yes' : 'No'}</p>
                <p><strong>External Links Ratio:</strong> ${(result.details.content_analysis.external_links_ratio * 100).toFixed(1)}%</p>
                <p><strong>Has Favicon:</strong> ${result.details.content_analysis.has_favicon ? 'Yes' : 'No'}</p>
                <p><strong>External Scripts Count:</strong> ${result.details.content_analysis.external_scripts_count}</p>
            </div>
            `}
        `;
        
        urlDetails.innerHTML = detailsHtml;
    }
    
    // Display Email Analysis Result
    function displayEmailResult(result) {
        // Update alert style and icon based on result
        const statusAlert = emailResult.querySelector('.alert');
        
        if (result.is_phishing === null) {
            // Unable to analyze
            emailStatusIcon.innerHTML = '<i class="fas fa-question-circle text-secondary"></i>';
            emailStatusTitle.textContent = 'Unable to Analyze';
            emailStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-secondary';
        } else if (result.is_phishing) {
            // Phishing detected
            emailStatusIcon.innerHTML = '<i class="fas fa-exclamation-triangle status-phishing"></i>';
            emailStatusTitle.textContent = 'Phishing Detected';
            emailStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-danger';
        } else if (result.confidence > 0.4) {
            // Suspicious
            emailStatusIcon.innerHTML = '<i class="fas fa-exclamation-circle status-suspicious"></i>';
            emailStatusTitle.textContent = 'Suspicious';
            emailStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-warning';
        } else {
            // Safe
            emailStatusIcon.innerHTML = '<i class="fas fa-check-circle status-safe"></i>';
            emailStatusTitle.textContent = 'Safe';
            emailStatusMessage.textContent = result.explanation;
            statusAlert.className = 'alert d-flex align-items-center alert-success';
        }
        
        // Generate detailed analysis
        let detailsHtml = `
            <div class="detail-section">
                <h5>Overview</h5>
                <div class="row mb-3">
                    <div class="col-md-6">
                        <p><strong>From:</strong> ${result.details.sender_analysis.from_address}</p>
                        <p><strong>Subject:</strong> ${result.details.subject_analysis.subject}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Phishing Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
                        <div class="confidence-meter">
                            <div class="confidence-fill" style="width: ${result.confidence * 100}%; background-color: ${getConfidenceColor(result.confidence)};"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Sender Analysis -->
            <div class="detail-section">
                <h5>Sender Analysis</h5>
                ${result.details.sender_analysis.display_name ? `<p><strong>Display Name:</strong> ${result.details.sender_analysis.display_name}</p>` : ''}
                <p><strong>Email:</strong> ${result.details.sender_analysis.email}</p>
                <p><strong>Domain:</strong> ${result.details.sender_analysis.domain}</p>
                ${generateDetailList(result.details.sender_analysis.suspicious_indicators)}
            </div>
            
            <!-- Subject Analysis -->
            <div class="detail-section">
                <h5>Subject Analysis</h5>
                ${result.details.subject_analysis.suspicious_keywords.length > 0 ? 
                    `<p><strong>Suspicious Keywords:</strong> ${result.details.subject_analysis.suspicious_keywords.join(', ')}</p>` : ''}
                ${result.details.subject_analysis.urgency_keywords.length > 0 ? 
                    `<p><strong>Urgency Keywords:</strong> ${result.details.subject_analysis.urgency_keywords.join(', ')}</p>` : ''}
                ${(result.details.subject_analysis.suspicious_keywords.length === 0 && 
                   result.details.subject_analysis.urgency_keywords.length === 0) ? 
                    '<p>No suspicious elements found in the subject line.</p>' : ''}
            </div>
            
            <!-- Body Analysis -->
            <div class="detail-section">
                <h5>Email Body Analysis</h5>
                <p><strong>Body Length:</strong> ${result.details.body_analysis.body_length} characters</p>
                <p><strong>URLs Found:</strong> ${result.details.body_analysis.urls_count}</p>
                <p><strong>Suspicious URLs:</strong> ${result.details.body_analysis.suspicious_urls_count}</p>
                ${result.details.body_analysis.suspicious_phrases.length > 0 ? 
                    `<p><strong>Suspicious Phrases:</strong> ${result.details.body_analysis.suspicious_phrases.join(', ')}</p>` : ''}
            </div>
            
            <!-- URLs Analysis -->
            <div class="detail-section">
                <h5>URLs Analysis</h5>
                <p><strong>Total URLs:</strong> ${result.details.urls_analysis.url_count}</p>
                <p><strong>Suspicious URLs:</strong> ${result.details.urls_analysis.suspicious_url_count}</p>
                ${result.details.urls_analysis.urls.length > 0 ? generateURLsList(result.details.urls_analysis.urls) : '<p>No URLs found in the email.</p>'}
            </div>
            
            <!-- Attachments Analysis -->
            <div class="detail-section">
                <h5>Attachments Analysis</h5>
                <p><strong>Total Attachments:</strong> ${result.details.attachments_analysis.attachment_count}</p>
                <p><strong>Suspicious Attachments:</strong> ${result.details.attachments_analysis.suspicious_attachment_count}</p>
                ${result.details.attachments_analysis.attachments.length > 0 ? 
                    generateAttachmentsList(result.details.attachments_analysis.attachments) : 
                    '<p>No attachments found in the email.</p>'}
            </div>
        `;
        
        emailDetails.innerHTML = detailsHtml;
    }
    
    // Helper function to generate a list of details
    function generateDetailList(items) {
        if (!items || items.length === 0) {
            return '<p>No suspicious indicators found.</p>';
        }
        
        let html = '<ul class="list-group">';
        items.forEach(item => {
            html += `<li class="list-group-item list-group-item-warning">${item}</li>`;
        });
        html += '</ul>';
        
        return html;
    }
    
    // Helper function to generate URLs list
    function generateURLsList(urls) {
        if (urls.length === 0) {
            return '<p>No URLs found.</p>';
        }
        
        let html = '<div class="table-responsive"><table class="table table-sm table-bordered">';
        html += '<thead><tr><th>URL</th><th>Domain</th><th>Status</th></tr></thead><tbody>';
        
        urls.forEach(url => {
            const statusClass = url.is_suspicious ? 'table-danger' : 'table-success';
            const status = url.is_suspicious ? 'Suspicious' : 'Safe';
            
            html += `<tr class="${statusClass}">
                <td>${url.url}</td>
                <td>${url.domain || 'N/A'}</td>
                <td>${status}</td>
            </tr>`;
        });
        
        html += '</tbody></table></div>';
        return html;
    }
    
    // Helper function to generate attachments list
    function generateAttachmentsList(attachments) {
        if (attachments.length === 0) {
            return '<p>No attachments found.</p>';
        }
        
        let html = '<div class="table-responsive"><table class="table table-sm table-bordered">';
        html += '<thead><tr><th>Filename</th><th>Content Type</th><th>Status</th></tr></thead><tbody>';
        
        attachments.forEach(attachment => {
            const statusClass = attachment.is_suspicious ? 'table-danger' : 'table-success';
            const status = attachment.is_suspicious ? 'Suspicious' : 'Safe';
            
            html += `<tr class="${statusClass}">
                <td>${attachment.filename}</td>
                <td>${attachment.content_type}</td>
                <td>${status}</td>
            </tr>`;
        });
        
        html += '</tbody></table></div>';
        return html;
    }
    
    // Helper function to get color based on confidence score
    function getConfidenceColor(confidence) {
        if (confidence < 0.3) return '#28a745';  // Green for safe
        if (confidence < 0.6) return '#fd7e14';  // Orange for suspicious
        return '#dc3545';  // Red for phishing
    }
    
    // Helper function to show alert
    function showAlert(element, message) {
        // Create alert
        const alert = document.createElement('div');
        alert.className = 'alert alert-danger alert-dismissible fade show mt-3';
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Insert after the form
        element.after(alert);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    }
});