"""
url_analyzer.py - Module to analyze URLs for phishing attempts
"""
import os
import pickle
import numpy as np
import tldextract
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
from tensorflow.keras.models import load_model

import sys
import os
# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.feature_extraction import URLFeatureExtractor, url_features_to_array

class URLAnalyzer:
    """Analyze URLs to detect phishing websites"""
    
    def __init__(self, use_neural_network=True):
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
        self.neural_network = None
        self.use_neural_network = use_neural_network
        self.load_models()
    
    def load_models(self):
        """Load the trained models"""
        # Load Random Forest model with absolute path
        rf_model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'url_classifier.pkl'))
        if os.path.exists(rf_model_path):
            with open(rf_model_path, 'rb') as f:
                self.model = pickle.load(f)
            print("URL Random Forest model loaded successfully")
        else:
            print(f"URL Random Forest model not found at {rf_model_path}")
        
        # Load Neural Network model if requested with absolute path
        if self.use_neural_network:
            nn_model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'url_neural_network.keras'))
            if os.path.exists(nn_model_path):
                try:
                    self.neural_network = load_model(nn_model_path)
                    print("URL Neural Network model loaded successfully")
                except Exception as e:
                    print(f"Error loading Neural Network model: {e}")
                    self.use_neural_network = False
            else:
                print(f"URL Neural Network model not found at {nn_model_path}")
                self.use_neural_network = False
        
        # Check if at least one model is loaded
        if self.model is None and self.neural_network is None:
            print("No URL models loaded. You need to train the models first.")
            return False
        
        return True
    def predict_with_neural_network(self, features_array):
        """
        Make prediction with neural network with proper input handling
        """
        try:
            # Convert to numpy array if not already
            if not isinstance(features_array, np.ndarray):
                features_array = np.array(features_array)
            
            # Add batch dimension if needed
            if len(features_array.shape) == 1:
                features_array = np.expand_dims(features_array, axis=0)
            
            # Convert to float32 which is what TensorFlow typically expects
            features_array = features_array.astype(np.float32)
            
            # Make prediction with error handling
            predictions = self.neural_network.predict(features_array, verbose=0)
            confidence = float(predictions[0][0])
            prediction = 1 if confidence > 0.5 else 0
            
            return prediction, confidence
        except Exception as e:
            print(f"Error during neural network prediction: {e}")
            # Fall back to Random Forest if available
            if self.model is not None:
                print("Falling back to Random Forest model")
                rf_prediction = self.model.predict([features_array[0]])[0]
                rf_confidence = self.model.predict_proba([features_array[0]])[0][1]
                return rf_prediction, rf_confidence
            else:
                print("No fallback model available")
                return 0, 0.5  # Default "safe" prediction
            

    def analyze_url(self, url, fetch_content=True):
        """
        Analyze a URL for phishing indicators
        
        Args:
            url (str): The URL to analyze
            fetch_content (bool): Whether to fetch and analyze the webpage content
            
        Returns:
            dict: Analysis results and detailed explanation
        """
        if self.model is None and self.neural_network is None:
            return {
                'is_phishing': None,
                'confidence': None,
                'explanation': "Models not loaded. Please train the models first.",
                'details': {}
            }
        
        # Extract URL features
        url_features = self.feature_extractor.extract_features(url)
        
        # Convert features to array for model input
        features_array = url_features_to_array(url_features)
        
        # Get predictions from both models (if available)
        rf_prediction = None
        rf_confidence = None
        nn_prediction = None
        nn_confidence = None
        
        if self.model is not None:
            rf_prediction = self.model.predict([features_array])[0]
            rf_confidence = self.model.predict_proba([features_array])[0][1]  # Probability of phishing class
        
        # Find this section in analyze_url method
# In analyze_url method
        if self.use_neural_network and self.neural_network is not None:
            try:
                nn_prediction, nn_confidence = self.predict_with_neural_network(features_array)
            except Exception as e:
                print(f"Error using neural network: {e}")
                # Fall back to RF prediction if available
                if self.model is not None:
                    nn_prediction = rf_prediction
                    nn_confidence = rf_confidence
                else:
                    nn_prediction = None
                    nn_confidence = None
                
        # Combine predictions (if both models available)
        if rf_prediction is not None and nn_prediction is not None:
            # Weighted average (neural network gets higher weight)
            confidence = 0.4 * rf_confidence + 0.6 * nn_confidence
            is_phishing = confidence > 0.5
        elif rf_prediction is not None:
            confidence = rf_confidence
            is_phishing = bool(rf_prediction)
        elif nn_prediction is not None:
            confidence = nn_confidence
            is_phishing = bool(nn_prediction)
        else:
            confidence = None
            is_phishing = None
        
        # Get content-based features if requested
        content_analysis = {}
        if fetch_content and is_phishing is not None:
            try:
                content_features = self.feature_extractor.fetch_url_content(url)
                
                # Update prediction based on content features
                # A simple heuristic: if the URL has login forms without HTTPS, it's likely phishing
                if content_features.get('has_login_form', False) and not url.startswith('https'):
                    confidence = max(confidence, 0.8)  # Increase confidence
                    is_phishing = True
                
                content_analysis = {
                    'has_login_form': content_features.get('has_login_form', False),
                    'has_password_field': content_features.get('has_password_field', False),
                    'external_links_ratio': content_features.get('external_links_ratio', 0),
                    'has_favicon': content_features.get('has_favicon', False),
                    'external_scripts_count': content_features.get('external_scripts_count', 0),
                    'is_suspicious': content_features.get('has_login_form', False) and not url.startswith('https')
                }
            except Exception as e:
                content_analysis = {
                    'error': str(e),
                    'is_suspicious': False
                }
        
        # Generate explanation
        explanation = self._generate_explanation(url, url_features, confidence, is_phishing)
        
        # Prepare detailed report
        result = {
            'is_phishing': is_phishing,
            'confidence': float(confidence) if confidence is not None else None,
            'explanation': explanation,
            'details': {
                'url_structure_analysis': self._analyze_url_structure(url),
                'domain_analysis': self._analyze_domain(url),
                'content_analysis': content_analysis,
                'security_analysis': self._analyze_security(url),
                'rf_prediction': bool(rf_prediction) if rf_prediction is not None else None,
                'rf_confidence': float(rf_confidence) if rf_confidence is not None else None,
                'nn_prediction': bool(nn_prediction) if nn_prediction is not None else None,
                'nn_confidence': float(nn_confidence) if nn_confidence is not None else None,
                'raw_features': url_features
            }
        }
        
        return result
    
    def _generate_explanation(self, url, features, confidence, is_phishing):
        """Generate a human-readable explanation of the phishing analysis"""
        if confidence is None or is_phishing is None:
            return "Unable to analyze the URL due to missing models."
        
        # Start building the explanation
        if is_phishing:
            if confidence > 0.8:
                explanation = "This URL has strong indicators of being a phishing website. "
            elif confidence > 0.6:
                explanation = "This URL has moderate indicators of being a phishing website. "
            else:
                explanation = "This URL has some suspicious elements that suggest it might be a phishing website. "
        else:
            if confidence < 0.2:
                explanation = "This URL appears to be legitimate with high confidence. "
            elif confidence < 0.4:
                explanation = "This URL appears to be legitimate, but has some unusual characteristics. "
            else:
                explanation = "This URL is probably legitimate, but has some suspicious elements. "
        
        # Add specific reasons based on URL analysis
        reasons = []
        
        # Parse URL components
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check for IP address instead of domain
        if features['has_ip_address']:
            reasons.append(f"The URL uses an IP address ({domain}) instead of a domain name")
        
        # Check for suspicious TLD
        if features['is_suspicious_tld']:
            tld = tldextract.extract(url).suffix
            reasons.append(f"The domain uses a suspicious top-level domain ({tld})")
        
        # Check for excessive subdomains
        if features['num_subdomains'] > 2:
            reasons.append(f"The URL has an unusual number of subdomains ({features['num_subdomains']})")
        
        # Check for URL length
        if features['url_length'] > 100:
            reasons.append(f"The URL is unusually long ({features['url_length']} characters)")
        
        # Check for special characters
        if features['has_at_symbol']:
            reasons.append("The URL contains an @ symbol, which can be used to hide the actual destination")
        
        if features['has_double_slash_redirect']:
            reasons.append("The URL contains a double slash redirect")
        
        if features['has_hex_characters']:
            reasons.append("The URL contains hexadecimal characters, which can be used to obfuscate the destination")
        
        # Check for HTTP instead of HTTPS
        if not features['uses_https']:
            reasons.append("The website doesn't use HTTPS encryption")
        
        # Check for dashes in domain
        if features['domain_dash_count'] > 0:
            reasons.append(f"The domain contains {features['domain_dash_count']} dashes, which is unusual for legitimate sites")
        
        # Check for suspicious keywords
        if features['has_suspicious_keywords']:
            reasons.append("The URL contains keywords commonly associated with phishing (like 'login', 'verify', etc.)")
        
        # Add the reasons to the explanation
        if reasons:
            explanation += "Key concerns include: " + "; ".join(reasons) + "."
        else:
            if is_phishing:
                explanation += "The combination of various subtle factors in this URL suggests it may be phishing."
            else:
                explanation += "The URL follows common patterns for legitimate websites."
        
        return explanation
    
    def _analyze_url_structure(self, url):
        """Analyze the URL structure for phishing indicators"""
        try:
            # Parse URL
            parsed_url = urlparse(url)
            scheme = parsed_url.scheme
            domain = parsed_url.netloc
            path = parsed_url.path
            query = parsed_url.query
            fragment = parsed_url.fragment
            
            # Check for suspicious indicators
            suspicious_indicators = []
            
            # Check URL length
            if len(url) > 100:
                suspicious_indicators.append(f"URL length ({len(url)} chars) is unusually long")
            
            # Check for IP address
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                suspicious_indicators.append("URL uses an IP address instead of a domain name")
            
            # Check for special characters
            if '@' in url:
                suspicious_indicators.append("URL contains @ symbol, which can be used to hide the real destination")
            
            if '//' in path:
                suspicious_indicators.append("URL contains double slash in the path, which can indicate a redirect")
            
            # Check for hexadecimal encoding
            if re.search(r'%[0-9a-fA-F]{2}', url):
                suspicious_indicators.append("URL contains hexadecimal encoding, which can be used to obfuscate the destination")
            
            # Check HTTP vs HTTPS
            if scheme != 'https':
                suspicious_indicators.append("URL doesn't use HTTPS encryption")
            
            # Analyze URL structure
            analysis = {
                'url': url,
                'scheme': scheme,
                'domain': domain,
                'path': path,
                'query': query,
                'fragment': fragment,
                'url_length': len(url),
                'path_length': len(path),
                'query_length': len(query),
                'suspicious_indicators': suspicious_indicators,
                'is_suspicious': len(suspicious_indicators) > 0
            }
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing URL structure: {e}")
            return {
                'url': url,
                'error': str(e),
                'is_suspicious': True
            }
    
    def _analyze_domain(self, url):
        """Analyze the domain for phishing indicators"""
        try:
            # Extract domain components
            ext = tldextract.extract(url)
            subdomain = ext.subdomain
            domain_name = ext.domain
            tld = ext.suffix
            
            # Check for suspicious indicators
            suspicious_indicators = []
            
            # Check for suspicious TLDs
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz']
            if tld in suspicious_tlds:
                suspicious_indicators.append(f"Domain uses suspicious TLD (.{tld})")
            
            # Check for excessive subdomains
            subdomain_parts = subdomain.split('.') if subdomain else []
            if len(subdomain_parts) > 2:
                suspicious_indicators.append(f"Domain has {len(subdomain_parts)} subdomains, which is unusual")
            
            # Check for dashes in domain
            if '-' in domain_name:
                suspicious_indicators.append("Domain name contains dashes, which is less common in legitimate sites")
            
            # Check for numeric characters in domain
            if re.search(r'\d', domain_name):
                suspicious_indicators.append("Domain name contains numbers, which is sometimes associated with temporary domains")
            
            # Check for lookalike domains (e.g., paypa1.com instead of paypal.com)
            common_domains = ['paypal.com', 'apple.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'google.com']
            full_domain = f"{domain_name}.{tld}"
            for legitimate_domain in common_domains:
                if full_domain != legitimate_domain and self._is_lookalike_domain(full_domain, legitimate_domain):
                    suspicious_indicators.append(f"Domain '{full_domain}' appears to be a lookalike of '{legitimate_domain}'")
            
            # Analyze domain
            analysis = {
                'domain': f"{domain_name}.{tld}",
                'subdomain': subdomain,
                'domain_name': domain_name,
                'tld': tld,
                'num_subdomains': len(subdomain_parts),
                'domain_length': len(domain_name),
                'suspicious_indicators': suspicious_indicators,
                'is_suspicious': len(suspicious_indicators) > 0
            }
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing domain: {e}")
            return {
                'domain': urlparse(url).netloc,
                'error': str(e),
                'is_suspicious': True
            }
    
    def _analyze_security(self, url):
        """Analyze the security aspects of the URL"""
        try:
            # Check if using HTTPS
            is_https = url.startswith('https://')
            
            # Try to get SSL certificate info if HTTPS
            cert_info = {}
            ssl_issues = []
            
            if is_https:
                try:
                    # Request with a short timeout
                    response = requests.get(url, timeout=5, verify=True)
                    # If we get here, SSL verification passed
                    has_valid_cert = True
                except requests.exceptions.SSLError:
                    has_valid_cert = False
                    ssl_issues.append("Invalid SSL certificate")
                except requests.exceptions.RequestException:
                    # Some other request error
                    has_valid_cert = None
                    ssl_issues.append("Could not verify SSL certificate")
            else:
                has_valid_cert = False
                ssl_issues.append("Not using HTTPS")
            
            # Security analysis
            analysis = {
                'is_https': is_https,
                'has_valid_cert': has_valid_cert,
                'ssl_issues': ssl_issues,
                'is_suspicious': not is_https or has_valid_cert is False
            }
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing security: {e}")
            return {
                'is_https': url.startswith('https://'),
                'error': str(e),
                'is_suspicious': True
            }
    
    def _is_lookalike_domain(self, domain1, domain2):
        """Check if domain1 is a lookalike of domain2"""
        # Simple check: if domains are very similar with small changes
        if domain1 == domain2:
            return False
            
        # Calculate edit distance
        return self._levenshtein_distance(domain1, domain2) <= 2
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]