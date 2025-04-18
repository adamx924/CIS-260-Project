"""
email_analyzer.py - Module to analyze emails for phishing attempts
(with fix for "index out of bounds" error)
"""
import os
import pickle
import numpy as np
import email as emaillib
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
# Use the fully-qualified import with the path relative to the project root
import sys
import os
# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.feature_extraction import EmailFeatureExtractor, email_features_to_array

class EmailAnalyzer:
    """Analyze emails to detect phishing attempts"""
    
    def __init__(self):
        self.feature_extractor = EmailFeatureExtractor()
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load the trained model"""
        # Use absolute path to the model
        model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'email_classifier.pkl'))
        
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            print("Email phishing detection model loaded successfully")
            return True
        else:
            print(f"Email model not found at {model_path}. You need to train the model first.")
            return False
    
    def analyze_email(self, email_content):
        """
        Analyze an email for phishing indicators
        
        Args:
            email_content (str): The raw email content
            
        Returns:
            dict: Analysis results with phishing probability
        """
        # If model is not loaded, return appropriate message
        if self.model is None:
            return {
                'is_phishing': None,
                'confidence': None,
                'explanation': "Model not loaded. Please train the model first.",
                'details': {}
            }
        
        # Extract features
        features = self.feature_extractor.extract_features(email_content)
        
        # Convert features to array for model input
        features_array = email_features_to_array(features)
        
        # Make prediction
        try:
            prediction = self.model.predict([features_array])[0]
            
            # FIX: Handle prediction probability safely
            predict_proba = self.model.predict_proba([features_array])[0]
            
            # Determine confidence based on model output shape
            if len(predict_proba) > 1:
                # Binary classifier with probabilities for both classes
                confidence = predict_proba[1]  # Probability of phishing class (index 1)
            else:
                # Single probability value (unusual but possible)
                confidence = predict_proba[0]
                
                # If the probability is for the negative class, adjust accordingly
                if prediction == 0:  # If prediction is negative class
                    confidence = 1.0 - confidence
        except Exception as e:
            print(f"Error during prediction: {e}")
            # Fallback to a basic prediction
            prediction = 0
            confidence = 0.0
            
        # Extract more details for explanation
        explanation = self._generate_explanation(email_content, features, confidence)
        
        # Get extracted URLs
        urls = self._extract_urls(email_content)
        
        # Determine overall classification and confidence
        is_phishing = bool(prediction)
        
        # Prepare detailed report
        result = {
            'is_phishing': is_phishing,
            'confidence': float(confidence),
            'explanation': explanation,
            'details': {
                'sender_analysis': self._analyze_sender(email_content),
                'subject_analysis': self._analyze_subject(email_content),
                'body_analysis': self._analyze_body(email_content),
                'urls_analysis': self._analyze_urls(urls),
                'attachments_analysis': self._analyze_attachments(email_content),
                'raw_features': features
            }
        }
        
        return result
    
    def _generate_explanation(self, email_content, features, confidence):
        """Generate a human-readable explanation of the phishing analysis"""
        # Parse the email
        msg = emaillib.message_from_string(email_content)
        
        # Extract basic components
        from_address = msg.get('From', '')
        subject = msg.get('Subject', '')
        
        # Start building the explanation
        if confidence > 0.8:
            explanation = "This email has strong indicators of being a phishing attempt. "
        elif confidence > 0.6:
            explanation = "This email has moderate indicators of being a phishing attempt. "
        elif confidence > 0.4:
            explanation = "This email has some suspicious elements but may not be a phishing attempt. "
        else:
            explanation = "This email appears to be legitimate. "
        
        # Add specific reasons based on features
        reasons = []
        
        # Only extract domain if from_address contains @
        sender_domain = ""
        if from_address and '@' in from_address:
            parts = from_address.split('@')
            if len(parts) > 1:
                sender_domain = parts[1].strip('>')
        
        if features['sender_has_suspicious_domain']:
            reasons.append(f"The sender domain '{sender_domain}' looks suspicious")
            
        if features['sender_domain_mismatch']:
            reasons.append("There's a mismatch between the sender's display name and their email domain")
            
        if features['subject_has_suspicious_keywords']:
            reasons.append(f"The subject line '{subject}' contains suspicious keywords")
            
        if features['subject_has_urgency']:
            reasons.append("The subject creates a false sense of urgency")
            
        if features['body_has_suspicious_phrases']:
            reasons.append("The email body contains phrases commonly used in phishing attempts")
            
        if features['body_has_excessive_urls']:
            reasons.append("The email contains an unusually high number of URLs")
            
        if features['body_contains_ip_urls']:
            reasons.append("The email contains links with IP addresses instead of domain names")
            
        if features['contains_suspicious_urls']:
            reasons.append("The email contains suspicious URLs")
            
        if features['url_domain_mismatch']:
            reasons.append("The URLs in the email don't match the sender's domain")
            
        if features['has_suspicious_attachments']:
            reasons.append("The email has potentially dangerous attachments")
            
        # Add the reasons to the explanation
        if reasons:
            explanation += "Key concerns include: " + "; ".join(reasons) + "."
        
        return explanation
    
    def _analyze_sender(self, email_content):
        """Analyze the sender information for phishing indicators"""
        msg = emaillib.message_from_string(email_content)
        from_address = msg.get('From', '')
        
        try:
            # Extract display name and email
            display_name = ""
            email = from_address
            
            if '<' in from_address:
                display_name = from_address.split('<')[0].strip()
                email = from_address.split('<')[1].split('>')[0]
            
            # Extract domain
            domain = ""
            if '@' in email:
                domain = email.split('@')[-1]
            
            # Check for suspicious indicators
            suspicious_indicators = []
            
            # Check for lookalike domains
            common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'paypal.com', 'amazon.com', 'facebook.com']
            for legitimate_domain in common_domains:
                if domain and domain != legitimate_domain and domain.lower().replace('1', 'l').replace('0', 'o') == legitimate_domain:
                    suspicious_indicators.append(f"Domain '{domain}' is a lookalike of '{legitimate_domain}'")
            
            # Check for brand name in display name but not in domain
            if display_name:
                common_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'bank', 'wells fargo', 'chase']
                for brand in common_brands:
                    if brand.lower() in display_name.lower() and domain and brand.lower() not in domain.lower():
                        suspicious_indicators.append(f"Display name contains '{brand}' but the domain doesn't match")
            
            # Analyze sender
            analysis = {
                'from_address': from_address,
                'display_name': display_name,
                'email': email,
                'domain': domain,
                'suspicious_indicators': suspicious_indicators,
                'is_suspicious': len(suspicious_indicators) > 0
            }
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing sender: {e}")
            return {
                'from_address': from_address,
                'error': str(e),
                'is_suspicious': False
            }
    
    def _analyze_subject(self, email_content):
        """Analyze the subject line for phishing indicators"""
        msg = emaillib.message_from_string(email_content)
        subject = msg.get('Subject', '')
        
        # Known suspicious keywords in subject lines
        suspicious_keywords = [
            'verify', 'account', 'password', 'banking', 'update', 'urgent', 
            'suspended', 'unusual', 'security', 'confirm', 'login'
        ]
        
        # Check for urgency indicators
        urgency_keywords = ['urgent', 'immediately', 'alert', 'warning', 'important', 'action required']
        
        # Find matches
        found_suspicious_keywords = [keyword for keyword in suspicious_keywords if keyword.lower() in subject.lower()]
        found_urgency_keywords = [keyword for keyword in urgency_keywords if keyword.lower() in subject.lower()]
        
        # Analyze subject
        analysis = {
            'subject': subject,
            'suspicious_keywords': found_suspicious_keywords,
            'urgency_keywords': found_urgency_keywords,
            'is_suspicious': len(found_suspicious_keywords) > 0 or len(found_urgency_keywords) > 0
        }
        
        return analysis
    
    def _analyze_body(self, email_content):
        """Analyze the email body for phishing indicators"""
        msg = emaillib.message_from_string(email_content)
        
        # Get email body
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode('utf-8', errors='ignore')
                    except:
                        # If decoding fails, try without decoding
                        payload = part.get_payload()
                        if payload:
                            body += str(payload)
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode('utf-8', errors='ignore')
            except:
                payload = msg.get_payload()
                if payload:
                    body = str(payload)
        
        # If body is HTML, extract text
        body_text = body
        if body and '<html' in body.lower():
            try:
                soup = BeautifulSoup(body, 'html.parser')
                extracted_text = soup.get_text()
                if extracted_text:
                    body_text = extracted_text
            except Exception as e:
                print(f"Error extracting text from HTML: {e}")
                # Keep the original body if BeautifulSoup fails
        
        # Known suspicious phrases in email bodies
        suspicious_phrases = [
            'verify your account', 'update your information', 'click here', 
            'confirm your details', 'your account has been suspended', 
            'security alert', 'unauthorized access', 'login immediately'
        ]
        
        # Find matches
        found_suspicious_phrases = [phrase for phrase in suspicious_phrases if phrase.lower() in body_text.lower()]
        
        # Extract URLs
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', body)
        
        # Check for suspicious URL patterns
        suspicious_urls = [url for url in urls if self._is_suspicious_url(url)]
        
        # Analyze body
        analysis = {
            'body_length': len(body_text),
            'suspicious_phrases': found_suspicious_phrases,
            'urls_count': len(urls),
            'suspicious_urls_count': len(suspicious_urls),
            'is_suspicious': len(found_suspicious_phrases) > 0 or len(suspicious_urls) > 0
        }
        
        return analysis
    
    def _extract_urls(self, email_content):
        """Extract all URLs from the email content"""
        # Parse the email
        msg = emaillib.message_from_string(email_content)
        
        # Get email body
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode('utf-8', errors='ignore')
                    except:
                        payload = part.get_payload()
                        if payload:
                            body += str(payload)
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode('utf-8', errors='ignore')
            except:
                payload = msg.get_payload()
                if payload:
                    body = str(payload)
        
        # Extract URLs using regex
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', body)
        
        return urls
    
    def _analyze_urls(self, urls):
        """Analyze extracted URLs for phishing indicators"""
        analyzed_urls = []
        
        for url in urls:
            try:
                # Parse URL
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                # Check for suspicious indicators
                is_ip_address = bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain))
                is_suspicious_tld = any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz'])
                has_suspicious_subdomain = domain.count('.') > 2
                
                # Known trusted domains (simplified list)
                trusted_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']
                is_trusted = any(domain.endswith(trusted) for trusted in trusted_domains)
                
                # Analyze URL
                url_analysis = {
                    'url': url,
                    'domain': domain,
                    'is_ip_address': is_ip_address,
                    'is_suspicious_tld': is_suspicious_tld,
                    'has_suspicious_subdomain': has_suspicious_subdomain,
                    'is_trusted': is_trusted,
                    'is_suspicious': is_ip_address or is_suspicious_tld or has_suspicious_subdomain
                }
                
                analyzed_urls.append(url_analysis)
                
            except Exception as e:
                analyzed_urls.append({
                    'url': url,
                    'error': str(e),
                    'is_suspicious': True
                })
        
        # Overall analysis
        overall_analysis = {
            'url_count': len(urls),
            'suspicious_url_count': sum(1 for url in analyzed_urls if url.get('is_suspicious', False)),
            'urls': analyzed_urls,
            'is_suspicious': any(url.get('is_suspicious', False) for url in analyzed_urls)
        }
        
        return overall_analysis
    
    def _analyze_attachments(self, email_content):
        """Analyze email attachments for potential threats"""
        msg = emaillib.message_from_string(email_content)
        
        attachments = []
        suspicious_extensions = ['.exe', '.bat', '.js', '.vbs', '.cmd', '.scr', '.pif']
        
        # Go through all parts of the email
        for part in msg.walk():
            filename = part.get_filename()
            
            if filename:
                # Check for suspicious file extensions
                is_suspicious = any(filename.lower().endswith(ext) for ext in suspicious_extensions)
                
                attachment_info = {
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'is_suspicious': is_suspicious
                }
                
                attachments.append(attachment_info)
        
        # Overall analysis
        overall_analysis = {
            'attachment_count': len(attachments),
            'suspicious_attachment_count': sum(1 for att in attachments if att['is_suspicious']),
            'attachments': attachments,
            'is_suspicious': any(att['is_suspicious'] for att in attachments)
        }
        
        return overall_analysis
    
    def _is_suspicious_url(self, url):
        """Check if a URL has phishing indicators"""
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check for suspicious indicators
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):  # IP address URL
                return True
                
            if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz']):  # Suspicious TLDs
                return True
                
            if domain.count('.') > 3:  # Excessive subdomains
                return True
                
            if len(domain) > 30:  # Unusually long domain
                return True
                
            return False
            
        except:
            return True  # If there's an error parsing the URL, consider it suspicious