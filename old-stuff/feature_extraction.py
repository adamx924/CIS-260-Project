"""
feature_extraction.py - Module to extract features from emails and URLs
(with fix for NoneType concatenation error)
"""
import re
import tldextract
import numpy as np
import email as emaillib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
import logging

class EmailFeatureExtractor:
    """Extract features from email content to detect phishing attempts"""
    
    def __init__(self):
        # Common phishing keywords in subject lines
        self.suspicious_subject_keywords = [
            'verify', 'account', 'password', 'banking', 'update', 'urgent', 
            'suspended', 'unusual', 'security', 'confirm', 'login'
        ]
        
        # Common phishing keywords in email bodies
        self.suspicious_body_keywords = [
            'verify your account', 'update your information', 'click here', 
            'confirm your details', 'your account has been suspended', 
            'security alert', 'unauthorized access', 'login immediately'
        ]
    
    def extract_features(self, email_content):
        """
        Extract phishing-related features from email content
        """
        try:
            msg = emaillib.message_from_string(email_content)
            
            # Extract basic components with None checks
            from_address = msg.get('From', '') or ''
            subject = msg.get('Subject', '') or ''
            
            # Get email body with error handling
            body = ''
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == 'text/plain' or content_type == 'text/html':
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:  # Check if payload exists
                                # FIX: Ensure we're not concatenating None to str
                                decoded_payload = payload.decode('utf-8', errors='ignore')
                                if decoded_payload:  # Check if decode returned something
                                    body += decoded_payload
                        except Exception as e:
                            # If decoding fails, try without decoding
                            payload = part.get_payload()
                            if payload:  # Check if payload exists
                                # FIX: Ensure we're not concatenating None to str
                                str_payload = str(payload)
                                if str_payload:  # Verify str conversion worked
                                    body += str_payload
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:  # Check if payload exists
                        # FIX: Ensure we're not concatenating None to str
                        decoded_payload = payload.decode('utf-8', errors='ignore')
                        if decoded_payload:  # Check if decode returned something
                            body = decoded_payload
                except Exception as e:
                    payload = msg.get_payload()
                    if payload:  # Check if payload exists
                        # FIX: Ensure we're not concatenating None to str
                        str_payload = str(payload)
                        if str_payload:  # Verify str conversion worked
                            body = str_payload
            
            # If body is HTML, extract text
            if body and '<html' in body.lower():
                try:
                    soup = BeautifulSoup(body, 'html.parser')
                    body_text = soup.get_text()
                    # FIX: Ensure we're not getting None from get_text()
                    body = body_text if body_text else body
                except Exception as e:
                    # If BeautifulSoup fails, keep the original HTML
                    pass
            
            # Extract URLs from the body
            urls = []
            if body:
                urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', body)
            
            # Check for IP URL bug fix: This might have been concatenating None
            ip_urls_check = False
            for url in urls:
                try:
                    domain_part = url.replace('http://', '').replace('https://', '')
                    ip_match = re.match(r'\d+\.\d+\.\d+\.\d+', domain_part)
                    if ip_match:
                        ip_urls_check = True
                        break
                except Exception as e:
                    # In case of any error processing a specific URL
                    continue
            
            # Extract features
            features = {
                # Sender features
                'sender_has_suspicious_domain': self._check_suspicious_domain(from_address),
                'sender_domain_age_less_than_year': True,  # This would require an API call to check domain age
                'sender_domain_mismatch': self._check_sender_domain_mismatch(from_address),
                
                # Subject features
                'subject_has_suspicious_keywords': any(keyword.lower() in subject.lower() for keyword in self.suspicious_subject_keywords),
                'subject_has_urgency': any(word in subject.lower() for word in ['urgent', 'immediately', 'alert', 'update needed']),
                
                # Body features
                'body_has_suspicious_phrases': any(phrase.lower() in body.lower() for phrase in self.suspicious_body_keywords),
                'body_has_excessive_urls': len(urls) > 3,
                'body_contains_ip_urls': ip_urls_check,  # Fixed check for IP URLs
                
                # URL features
                'contains_suspicious_urls': any(self._check_suspicious_url(url) for url in urls),
                'url_domain_mismatch': any(self._check_url_domain_mismatch(url, from_address) for url in urls),
                
                # Attachment features
                'has_suspicious_attachments': any(part.get_filename() and part.get_filename().endswith(('.exe', '.bat', '.js')) for part in msg.walk() if part.get_filename())
            }
            
            return features
            
        except Exception as e:
            print(f"Error extracting email features: {e}")
            # Return default features in case of error
            return {
                'sender_has_suspicious_domain': False,
                'sender_domain_age_less_than_year': False,
                'sender_domain_mismatch': False,
                'subject_has_suspicious_keywords': False,
                'subject_has_urgency': False,
                'body_has_suspicious_phrases': False,
                'body_has_excessive_urls': False,
                'body_contains_ip_urls': False,
                'contains_suspicious_urls': False,
                'url_domain_mismatch': False,
                'has_suspicious_attachments': False
            }
    
    def _check_suspicious_domain(self, from_address):
        """Check if sender domain looks suspicious"""
        try:
            # Extract domain from email address
            if '@' not in from_address:
                return False
                
            domain = from_address.split('@')[1].strip('>')
            
            # Check for lookalike domains (e.g., paypa1.com instead of paypal.com)
            common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'paypal.com', 'amazon.com', 'facebook.com']
            for legitimate_domain in common_domains:
                # Check for character substitution (e.g., '1' instead of 'l')
                if domain != legitimate_domain and self._is_lookalike_domain(domain, legitimate_domain):
                    return True
            
            return False
        except Exception as e:
            print(f"Error in _check_suspicious_domain: {e}")
            return False
    
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
    
    def _check_sender_domain_mismatch(self, from_address):
        """Check if sender's display name mismatches with the actual email domain"""
        try:
            # Ensure from_address is a string
            if not from_address or not isinstance(from_address, str):
                return False
                
            # Example: "PayPal <phishing@malicious.com>"
            # Extract display name and actual email
            display_name = ""
            email = from_address
            
            if '<' in from_address and '>' in from_address:
                parts = from_address.split('<', 1)
                if len(parts) > 1:
                    display_name = parts[0].strip().lower()
                    email_part = parts[1].split('>', 1)[0].lower()
                    if '@' in email_part:
                        email = email_part
            
            # Ensure email is valid
            if not email or '@' not in email:
                return False
                
            domain = email.split('@')[1]
            
            # Check if display name contains a well-known brand but domain doesn't match
            common_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'instagram', 'bank', 'wellsfargo', 'chase']
            for brand in common_brands:
                if brand in display_name and brand not in domain:
                    return True
            
            return False
        except Exception as e:
            print(f"Error in _check_sender_domain_mismatch: {e}")
            return False
    
    def _check_suspicious_url(self, url):
        """Check if URL has phishing characteristics"""
        try:
            # Extract domain
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check for IP address URLs
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return True
                
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
                
            # Check for excessive subdomains
            if domain.count('.') > 3:
                return True
                
            # Check for long domains
            if len(domain) > 30:
                return True
                
            return False
        except Exception as e:
            print(f"Error in _check_suspicious_url: {e}")
            return False
    
    def _check_url_domain_mismatch(self, url, from_address):
        """Check if URL domain doesn't match sender's domain"""
        try:
            # Extract sender domain
            if '@' not in from_address:
                return False
                
            sender_domain = from_address.split('@')[1].strip('>')
            
            # Extract URL domain
            parsed_url = urlparse(url)
            url_domain = parsed_url.netloc
            
            # Compare extracted domains (allow for subdomains)
            return not (sender_domain in url_domain or url_domain in sender_domain)
        except Exception as e:
            print(f"Error in _check_url_domain_mismatch: {e}")
            return False

# Rest of the code remains the same...

class URLFeatureExtractor:
    """Extract features from URLs to detect phishing websites"""
    logger = logging.getLogger('phishblock')
    def __init__(self):
        # Suspicious URL patterns
        self.suspicious_keywords = ['login', 'verify', 'account', 'secure', 'banking', 'signin', 'payment']
        
    def extract_features(self, url):
        """
        Extract phishing-related features from a URL
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Dictionary of extracted features
        """
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            query = parsed_url.query
            
            # Extract domain components
            ext = tldextract.extract(url)
            subdomain = ext.subdomain
            domain_name = ext.domain
            tld = ext.suffix
            
            # Extract features
            features = {
                # URL structure features
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(path),
                'num_dots': domain.count('.'),
                'has_ip_address': bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)),
                'has_at_symbol': '@' in url,
                'has_double_slash_redirect': '//' in path,
                'has_hex_characters': bool(re.search(r'%[0-9a-fA-F]{2}', url)),
                'num_subdomains': len(subdomain.split('.')) if subdomain else 0,
                
                # Domain features
                'is_suspicious_tld': tld in ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz'],
                'domain_dash_count': domain.count('-'),
                'domain_underscore_count': domain.count('_'),
                'subdomain_depth': len(subdomain.split('.')) if subdomain else 0,
                
                # Content features
                'has_suspicious_keywords': any(keyword in url.lower() for keyword in self.suspicious_keywords),
                
                # HTTPS features
                'uses_https': parsed_url.scheme == 'https',
                
                # Query features
                'query_length': len(query),
                'num_query_components': len(query.split('&')) if query else 0
            }
            
            return features
            
        except Exception as e:
            print(f"Error extracting URL features: {e}")
            # Return default features in case of error
            return {
                'url_length': 0,
                'domain_length': 0,
                'path_length': 0,
                'num_dots': 0,
                'has_ip_address': False,
                'has_at_symbol': False,
                'has_double_slash_redirect': False,
                'has_hex_characters': False,
                'num_subdomains': 0,
                'is_suspicious_tld': False,
                'domain_dash_count': 0,
                'domain_underscore_count': 0,
                'subdomain_depth': 0,
                'has_suspicious_keywords': False,
                'uses_https': False,
                'query_length': 0,
                'num_query_components': 0
            }
            
    def fetch_url_content(self, url):
        """
        Fetch and analyze content from a URL (with timeout and error handling)
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Dictionary of content-based features
        """
        try:
            # Set a timeout to avoid getting stuck on malicious sites
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            
            if response.status_code == 200:
                # Parse HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract content features
                login_forms = len(soup.find_all('form'))
                password_fields = len(soup.find_all('input', {'type': 'password'}))
                external_links = len([link for link in soup.find_all('a', href=True) if link['href'].startswith('http') and url not in link['href']])
                
                # Check for favicon (legitimate sites typically have favicons)
                has_favicon = bool(soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon'))
                
                # Check for external JavaScript (phishing sites often load external scripts)
                external_scripts = len([script for script in soup.find_all('script', src=True) if script['src'].startswith('http') and url not in script['src']])
                
                # Extract features
                content_features = {
                    'has_login_form': login_forms > 0,
                    'has_password_field': password_fields > 0,
                    'external_links_ratio': external_links / max(1, len(soup.find_all('a', href=True))) if soup.find_all('a', href=True) else 0,
                    'has_favicon': has_favicon,
                    'external_scripts_count': external_scripts
                }
                
                return content_features
            else:
                # Return default features if page doesn't load
                return {
                    'has_login_form': False,
                    'has_password_field': False,
                    'external_links_ratio': 0,
                    'has_favicon': False,
                    'external_scripts_count': 0
                }
                
        except Exception as e:
            print(f"Error fetching URL content: {e}")
            # Return default features in case of error
            return {
                'has_login_form': False,
                'has_password_field': False,
                'external_links_ratio': 0,
                'has_favicon': False,
                'external_scripts_count': 0
            }

# Functions to convert features to numerical arrays for model input
def email_features_to_array(features):
    """Convert email features dictionary to a numerical array for model input"""
    feature_order = [
        'sender_has_suspicious_domain',
        'sender_domain_age_less_than_year',
        'sender_domain_mismatch',
        'subject_has_suspicious_keywords',
        'subject_has_urgency',
        'body_has_suspicious_phrases',
        'body_has_excessive_urls',
        'body_contains_ip_urls',
        'contains_suspicious_urls',
        'url_domain_mismatch',
        'has_suspicious_attachments'
    ]
    
    # Convert boolean values to integers (0 or 1)
    return np.array([int(features[feature]) for feature in feature_order])

def url_features_to_array(features):
    """Convert URL features dictionary to a numerical array for model input"""
    feature_order = [
        'url_length',
        'domain_length',
        'path_length',
        'num_dots',
        'has_ip_address',
        'has_at_symbol',
        'has_double_slash_redirect',
        'has_hex_characters',
        'num_subdomains',
        'is_suspicious_tld',
        'domain_dash_count',
        'domain_underscore_count',
        'subdomain_depth',
        'has_suspicious_keywords',
        'uses_https',
        'query_length',
        'num_query_components'
    ]
    
    # Convert to appropriate numerical values
    return np.array([
        features[feature] if not isinstance(features[feature], bool) else int(features[feature])
        for feature in feature_order
    ])