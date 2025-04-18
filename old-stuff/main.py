"""
main.py - Main entry point for PhishBlock
"""
import os
import sys
import argparse
import logging
from src.model_training import EmailModelTrainer, URLModelTrainer
from src.email_analyzer import EmailAnalyzer
from src.url_analyzer import URLAnalyzer

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

def setup_environment():
    """
    Setup the PhishBlock environment by creating necessary directories
    """
    # Create directories if they don't exist
    os.makedirs('data/phishing_emails', exist_ok=True)
    os.makedirs('data/legitimate_emails', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    os.makedirs('web/static/css', exist_ok=True)
    os.makedirs('web/static/js', exist_ok=True)
    os.makedirs('web/templates', exist_ok=True)
    
    logger.info("Environment setup complete")

def train_models():
    """
    Train the phishing detection models
    """
    logger.info("Starting model training...")
    
    # Train email model
    email_trainer = EmailModelTrainer()
    email_trainer.train_model()
    
    # Train URL model
    url_trainer = URLModelTrainer()
    url_trainer.train_neural_network()  # This also trains the RandomForest model
    
    logger.info("Model training complete")

def start_web_server():
    """
    Start the Flask web server
    """
    logger.info("Starting web server...")
    
    # Change to web directory
    os.chdir('web')
    
    # Run Flask app
    os.system("python app.py")

def analyze_url(url):
    """
    Analyze a single URL from the command line
    
    Args:
        url (str): The URL to analyze
    """
    logger.info(f"Analyzing URL: {url}")
    
    # Initialize URL analyzer
    analyzer = URLAnalyzer()
    
    # Normalize URL
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    # Analyze URL
    result = analyzer.analyze_url(url)
    
    # Print result
    print("\n===== URL Analysis Result =====")
    print(f"URL: {url}")
    print(f"Status: {'Phishing' if result['is_phishing'] else 'Legitimate'}")
    print(f"Confidence: {result['confidence'] * 100:.1f}%")
    print(f"Explanation: {result['explanation']}")
    print("\nDetailed Analysis:")
    
    # Print domain analysis
    domain_analysis = result['details']['domain_analysis']
    print(f"\nDomain: {domain_analysis['domain']}")
    if domain_analysis['suspicious_indicators']:
        print("Suspicious indicators:")
        for indicator in domain_analysis['suspicious_indicators']:
            print(f"  - {indicator}")
    else:
        print("No suspicious domain indicators found")
    
    # Print security analysis
    security_analysis = result['details']['security_analysis']
    print(f"\nSecurity:")
    print(f"  HTTPS: {'Yes' if security_analysis['is_https'] else 'No'}")
    if security_analysis['ssl_issues']:
        print("  SSL issues:")
        for issue in security_analysis['ssl_issues']:
            print(f"    - {issue}")
    
    print("\n===============================")

def analyze_email(email_path):
    """
    Analyze a single email file from the command line
    
    Args:
        email_path (str): Path to the email file
    """
    logger.info(f"Analyzing email: {email_path}")
    
    # Check if file exists
    if not os.path.exists(email_path):
        print(f"Error: File not found - {email_path}")
        return
    
    # Read email content
    with open(email_path, 'r', errors='ignore') as f:
        email_content = f.read()
    
    # Initialize email analyzer
    analyzer = EmailAnalyzer()
    
    # Analyze email
    result = analyzer.analyze_email(email_content)
    
    # Print result
    print("\n===== Email Analysis Result =====")
    print(f"Status: {'Phishing' if result['is_phishing'] else 'Legitimate'}")
    print(f"Confidence: {result['confidence'] * 100:.1f}%")
    print(f"Explanation: {result['explanation']}")
    print("\nDetailed Analysis:")
    
    # Print sender analysis
    sender_analysis = result['details']['sender_analysis']
    print(f"\nFrom: {sender_analysis['from_address']}")
    if sender_analysis['suspicious_indicators']:
        print("Suspicious sender indicators:")
        for indicator in sender_analysis['suspicious_indicators']:
            print(f"  - {indicator}")
    
    # Print subject analysis
    subject_analysis = result['details']['subject_analysis']
    print(f"\nSubject: {subject_analysis['subject']}")
    if subject_analysis['suspicious_keywords'] or subject_analysis['urgency_keywords']:
        print("Suspicious subject indicators:")
        for keyword in subject_analysis['suspicious_keywords']:
            print(f"  - Contains suspicious keyword: {keyword}")
        for keyword in subject_analysis['urgency_keywords']:
            print(f"  - Creates false sense of urgency: {keyword}")
    
    # Print URLs found
    urls_analysis = result['details']['urls_analysis']
    print(f"\nURLs found: {urls_analysis['url_count']}")
    print(f"Suspicious URLs: {urls_analysis['suspicious_url_count']}")
    
    if urls_analysis['urls']:
        print("\nURLs in email:")
        for url_info in urls_analysis['urls']:
            status = "⚠️ Suspicious" if url_info.get('is_suspicious') else "✓ Safe"
            print(f"  - {url_info['url']} ({status})")
    
    # Print attachments
    attachments_analysis = result['details']['attachments_analysis']
    print(f"\nAttachments: {attachments_analysis['attachment_count']}")
    print(f"Suspicious attachments: {attachments_analysis['suspicious_attachment_count']}")
    
    if attachments_analysis['attachments']:
        print("\nAttachments in email:")
        for attachment in attachments_analysis['attachments']:
            status = "⚠️ Suspicious" if attachment['is_suspicious'] else "✓ Safe"
            print(f"  - {attachment['filename']} ({status})")
    
    print("\n==================================")

def main():
    """
    Main entry point for PhishBlock
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='PhishBlock - Phishing Detection Tool')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Setup PhishBlock environment')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the phishing detection models')
    
    # Web command
    web_parser = subparsers.add_parser('web', help='Start the web server')
    
    # URL analysis command
    url_parser = subparsers.add_parser('url', help='Analyze a URL')
    url_parser.add_argument('url', help='The URL to analyze')
    
    # Email analysis command
    email_parser = subparsers.add_parser('email', help='Analyze an email file')
    email_parser.add_argument('file', help='Path to the email file')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute command
    if args.command == 'setup':
        setup_environment()
    elif args.command == 'train':
        train_models()
    elif args.command == 'web':
        start_web_server()
    elif args.command == 'url':
        analyze_url(args.url)
    elif args.command == 'email':
        analyze_email(args.file)
    else:
        # Default: show help
        parser.print_help()

if __name__ == "__main__":
    main()