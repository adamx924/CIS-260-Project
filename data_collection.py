"""
data_collection.py - Script to collect and organize phishing and legitimate data
"""
import os
import csv
import requests
import pandas as pd
from bs4 import BeautifulSoup
import pickle

# Create necessary directories
os.makedirs('data/phishing_emails', exist_ok=True)
os.makedirs('data/legitimate_emails', exist_ok=True)
os.makedirs('models', exist_ok=True)

def download_phishing_urls():
    """
    Download phishing URLs from PhishTank or similar repositories
    """
    print("Downloading phishing URLs dataset...")
    
    # PhishTank offers an API for downloading phishing URL datasets
    # You'll need to register and get an API key
    # This is a simplified example
    phishtank_url = "https://data.phishtank.com/data/your-api-key/online-valid.csv"
    
    try:
        # For demonstration, we'll create a sample dataset
        # In a real implementation, you would download from PhishTank or similar sources
        phishing_urls = [
            {"url": "http://fake-paypal.com/login", "label": 1},
            {"url": "http://banking-secure-login.com", "label": 1},
            {"url": "http://amazon-account-verify.net", "label": 1},
            # Add more examples...
        ]
        
        # Save to CSV
        with open('data/phishing_urls.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["url", "label"])
            writer.writeheader()
            writer.writerows(phishing_urls)
            
        print(f"Saved {len(phishing_urls)} phishing URLs")
        
    except Exception as e:
        print(f"Error downloading phishing URLs: {e}")

def collect_legitimate_urls():
    """
    Collect legitimate URLs from trusted sources
    """
    print("Collecting legitimate URLs...")
    
    # For demonstration, we'll create sample data
    # In a real implementation, you would collect from trusted sources
    legitimate_urls = [
        {"url": "https://www.google.com", "label": 0},
        {"url": "https://www.amazon.com", "label": 0},
        {"url": "https://www.paypal.com", "label": 0},
        {"url": "https://www.facebook.com", "label": 0},
        # Add more examples...
    ]
    
    # Save to CSV
    with open('data/legitimate_urls.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(legitimate_urls)
        
    print(f"Saved {len(legitimate_urls)} legitimate URLs")

def collect_email_samples():
    """
    Collect email samples (this would normally involve downloading from repositories)
    """
    print("Collecting email samples...")
    
    # You can use public email datasets or create your own samples
    # For demonstration, we'll create placeholder files
    
    # Phishing email example
    phishing_email = """
    From: service@paypa1.com
    Subject: Your account has been limited
    
    Dear valued customer,
    
    We have noticed suspicious activity on your account. Please verify your information immediately by clicking on the link below:
    
    [Click here to verify](http://paypa1-secure.com/verify)
    
    Thank you,
    Security Team
    """
    
    # Legitimate email example
    legitimate_email = """
    From: newsletter@amazon.com
    Subject: Your Weekly Amazon Deals
    
    Hello Customer,
    
    Check out this week's deals on Amazon:
    
    - 20% off Electronics
    - Free shipping on orders over $25
    
    Visit amazon.com to learn more.
    
    Thanks,
    Amazon Team
    """
    
    # Save samples
    with open('data/phishing_emails/sample1.txt', 'w') as f:
        f.write(phishing_email)
        
    with open('data/legitimate_emails/sample1.txt', 'w') as f:
        f.write(legitimate_email)
    
    print("Saved email samples")

if __name__ == "__main__":
    download_phishing_urls()
    collect_legitimate_urls()
    collect_email_samples()
    print("Data collection complete!")