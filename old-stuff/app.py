"""
app.py - Flask web application for PhishBlock
"""
from flask import Flask, render_template, request, jsonify
import os
import sys
import json
import numpy as np

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from email_analyzer import EmailAnalyzer
from url_analyzer import URLAnalyzer
app = Flask(__name__)

# Initialize analyzers
# Initialize analyzers (ensure these lines are within the correct scope)
email_analyzer = EmailAnalyzer()
url_analyzer = URLAnalyzer()

# You might want to print the status of the analyzers to debug
print(f"Email analyzer model loaded: {email_analyzer.model is not None}")
print(f"URL analyzer models loaded: RF={url_analyzer.model is not None}, NN={url_analyzer.neural_network is not None}")

@app.route('/')
def index():
    """Render the home page"""
    return render_template('index.html')

@app.route('/analyze_email', methods=['POST'])
def analyze_email_route():
    """API endpoint to analyze an email"""
    try:
        # Get email content from form
        email_content = request.form.get('email_content', '')
        
        if not email_content:
            return jsonify({
                'success': False,
                'error': 'No email content provided'
            })
        
        # Analyze the email
        result = email_analyzer.analyze_email(email_content)
        
        # Convert NumPy types to Python native types
        result = convert_numpy_types(result)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/analyze_url', methods=['POST'])
def analyze_url_route():
    """API endpoint to analyze a URL"""
    try:
        # Get URL from form
        url = request.form.get('url', '')
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'No URL provided'
            })
        
        # Add http:// if missing
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        # Analyze the URL
        result = url_analyzer.analyze_url(url)
        
        # Convert NumPy types to Python native types
        result = convert_numpy_types(result)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })
def convert_numpy_types(obj):
    """
    Recursively convert NumPy types to Python native types for JSON serialization
    """

    
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, np.bool_):
        return bool(obj)
    else:
        return obj
@app.route('/train_models', methods=['POST'])
def train_models_route():
    """API endpoint to train the models"""
    try:
        # This would normally trigger a background task
        from model_training import EmailModelTrainer, URLModelTrainer
        
        # Train models
        email_trainer = EmailModelTrainer()
        email_trainer.train_model()
        
        url_trainer = URLModelTrainer()
        url_trainer.train_neural_network()
        
        # Reload the models
        global email_analyzer, url_analyzer
        email_analyzer = EmailAnalyzer()
        url_analyzer = URLAnalyzer()
        
        return jsonify({
            'success': True,
            'message': 'Models trained and loaded successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True)