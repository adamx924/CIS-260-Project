"""
utils.py - Utility functions for PhishBlock
"""
import re
import os
import logging
import requests
import tldextract
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishblock.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('phishblock')

def is_valid_url(url):
    """
    Check if a URL is valid
    
    Args:
        url (str): The URL to check
        
    Returns:
        bool: True if the URL is valid, False otherwise
    """
    try:
        # Basic URL validation using regex
        pattern = re.compile(
            r'^(?:http|https)://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ipv4
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(re.match(pattern, url))
    except:
        return False

def is_valid_email_content(content):
    """
    Check if the content looks like an email
    
    Args:
        content (str): The content to check
        
    Returns:
        bool: True if the content looks like an email, False otherwise
    """
    # Check for common email headers
    common_headers = ['From:', 'To:', 'Subject:', 'Date:', 'Received:']
    
    # Count how many headers are present
    header_count = sum(1 for header in common_headers if header in content)
    
    # If at least two headers are present, it's likely an email
    return header_count >= 2

def check_domain_age(domain):
    """
    Check the age of a domain using WHOIS
    
    Args:
        domain (str): The domain to check
        
    Returns:
        dict: Domain age information with keys:
              - 'age_days': int or None
              - 'creation_date': datetime or None
              - 'is_recent': bool (True if domain is less than 6 months old)
    """
    try:
        # Try to use python-whois if available
        import whois
        domain_info = whois.whois(domain)
        
        creation_date = domain_info.creation_date
        
        # Handle case where creation_date is a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            is_recent = age_days < 180  # Less than 6 months
            
            return {
                'age_days': age_days,
                'creation_date': creation_date,
                'is_recent': is_recent
            }
    except:
        # If whois query fails or module not available
        pass
    
    # Default return if we couldn't get the information
    return {
        'age_days': None,
        'creation_date': None,
        'is_recent': None
    }

def check_ssl_certificate(url):
    """
    Check the SSL certificate of a website
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: SSL certificate information with keys:
              - 'has_ssl': bool
              - 'is_valid': bool
              - 'issuer': str or None
              - 'expires': datetime or None
              - 'is_expired': bool or None
    """
    try:
        # Only check HTTPS URLs
        if not url.startswith('https://'):
            return {
                'has_ssl': False,
                'is_valid': False,
                'issuer': None,
                'expires': None,
                'is_expired': None
            }
        
        # Try to connect with certificate validation
        response = requests.get(url, timeout=5, verify=True)
        
        # If we get here, the certificate is valid
        # In a real implementation, you would extract more certificate details
        return {
            'has_ssl': True,
            'is_valid': True,
            'issuer': 'Unknown',  # Would require deeper certificate inspection
            'expires': None,      # Would require deeper certificate inspection
            'is_expired': False   # We know it's not expired if the request succeeded
        }
    except requests.exceptions.SSLError:
        # Certificate validation failed
        return {
            'has_ssl': True,
            'is_valid': False,
            'issuer': None,
            'expires': None,
            'is_expired': None
        }
    except:
        # Request failed for other reasons
        return {
            'has_ssl': None,
            'is_valid': None,
            'issuer': None,
            'expires': None,
            'is_expired': None
        }

def normalize_url(url):
    """
    Normalize a URL by adding http:// if missing
    
    Args:
        url (str): The URL to normalize
        
    Returns:
        str: The normalized URL
    """
    if not url:
        return url
        
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    return url

def extract_domain_info(url):
    """
    Extract domain information from a URL
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Domain information with keys:
              - 'subdomain': str
              - 'domain': str
              - 'tld': str
              - 'registered_domain': str
    """
    try:
        ext = tldextract.extract(url)
        
        return {
            'subdomain': ext.subdomain,
            'domain': ext.domain,
            'tld': ext.suffix,
            'registered_domain': f"{ext.domain}.{ext.suffix}"
        }
    except:
        # Return empty values if extraction fails
        return {
            'subdomain': '',
            'domain': '',
            'tld': '',
            'registered_domain': ''
        }

def get_safe_browsing_status(url, api_key=None):
    """
    Check if a URL is in the Google Safe Browsing blacklist
    
    Args:
        url (str): The URL to check
        api_key (str): Google Safe Browsing API key
        
    Returns:
        dict: Safe browsing status with keys:
              - 'is_safe': bool
              - 'threats': list or None
    """
    # If no API key is provided, skip the check
    if not api_key:
        return {
            'is_safe': None,
            'threats': None
        }
        
    try:
        # Google Safe Browsing API v4 endpoint
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        # Prepare the request payload
        payload = {
            "client": {
                "clientId": "phishblock",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        
        # Send the request
        response = requests.post(endpoint, json=payload)
        data = response.json()
        
        # Check if any threats were found
        if 'matches' in data and data['matches']:
            return {
                'is_safe': False,
                'threats': [match['threatType'] for match in data['matches']]
            }
        else:
            return {
                'is_safe': True,
                'threats': []
            }
    except:
        # Return None if the check fails
        return {
            'is_safe': None,
            'threats': None
        }

def levenshtein_distance(s1, s2):
    """
    Calculate the Levenshtein distance between two strings
    
    Args:
        s1 (str): First string
        s2 (str): Second string
        
    Returns:
        int: The Levenshtein distance
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
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