"""
model_training.py - Module to train phishing detection models
"""
import os
import glob
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from .feature_extraction import EmailFeatureExtractor, URLFeatureExtractor, email_features_to_array, url_features_to_array

class EmailModelTrainer:
    """Train a model to classify phishing emails"""
    
    def __init__(self):
        self.feature_extractor = EmailFeatureExtractor()
        self.model = None
    
    def prepare_data(self):
        """Prepare training data from email samples"""
        phishing_emails = []
        legitimate_emails = []
        
        # Load phishing email samples
        for filename in glob.glob('data/phishing_emails/*.txt'):
            with open(filename, 'r', errors='ignore') as file:
                phishing_emails.append(file.read())
        
        # Load legitimate email samples
        for filename in glob.glob('data/legitimate_emails/*.txt'):
            with open(filename, 'r', errors='ignore') as file:
                legitimate_emails.append(file.read())
        
        print(f"Loaded {len(phishing_emails)} phishing emails and {len(legitimate_emails)} legitimate emails")
        
        # Extract features
        phishing_features = [self.feature_extractor.extract_features(email) for email in phishing_emails]
        legitimate_features = [self.feature_extractor.extract_features(email) for email in legitimate_emails]
        
        # Convert to numerical arrays
        X_phishing = np.array([email_features_to_array(features) for features in phishing_features])
        X_legitimate = np.array([email_features_to_array(features) for features in legitimate_features])
        
        # Create labels (1 for phishing, 0 for legitimate)
        y_phishing = np.ones(len(X_phishing))
        y_legitimate = np.zeros(len(X_legitimate))
        
        # Combine datasets
        X = np.vstack((X_phishing, X_legitimate))
        y = np.hstack((y_phishing, y_legitimate))
        
        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        return X_train, X_test, y_train, y_test
    
    def train_model(self):
        """Train a Random Forest classifier for email phishing detection"""
        print("Training email phishing detection model...")
        
        # Prepare data
        X_train, X_test, y_train, y_test = self.prepare_data()
        
        # Initialize and train Random Forest model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        
        print(f"Model accuracy: {accuracy:.4f}")
        print("Classification report:")
        print(report)
        
        # Save the model
        with open('models/email_classifier.pkl', 'wb') as f:
            pickle.dump(self.model, f)
        
        print("Email phishing detection model saved to models/email_classifier.pkl")
    
    def load_model(self):
        """Load a trained model from disk"""
        try:
            with open('models/email_classifier.pkl', 'rb') as f:
                self.model = pickle.load(f)
            print("Email phishing detection model loaded successfully")
            return True
        except Exception as e:
            print(f"Error loading email model: {e}")
            return False


class URLModelTrainer:
    """Train a model to classify phishing URLs"""
    
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
    
    def prepare_data(self):
        """Prepare training data from URL datasets"""
        # Load phishing URLs
        phishing_df = pd.read_csv('data/phishing_urls.csv')
        
        # Load legitimate URLs
        legitimate_df = pd.read_csv('data/legitimate_urls.csv')
        
        print(f"Loaded {len(phishing_df)} phishing URLs and {len(legitimate_df)} legitimate URLs")
        
        # Extract features
        phishing_features = [self.feature_extractor.extract_features(url) for url in phishing_df['url']]
        legitimate_features = [self.feature_extractor.extract_features(url) for url in legitimate_df['url']]
        
        # Convert to numerical arrays
        X_phishing = np.array([url_features_to_array(features) for features in phishing_features])
        X_legitimate = np.array([url_features_to_array(features) for features in legitimate_features])
        
        # Create labels (1 for phishing, 0 for legitimate)
        y_phishing = np.ones(len(X_phishing))
        y_legitimate = np.zeros(len(X_legitimate))
        
        # Combine datasets
        X = np.vstack((X_phishing, X_legitimate))
        y = np.hstack((y_phishing, y_legitimate))
        
        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        return X_train, X_test, y_train, y_test
    
    def train_neural_network(self):
        """Train a neural network for URL phishing detection"""
        print("Training neural network for URL phishing detection...")
        
        # Prepare data
        X_train, X_test, y_train, y_test = self.prepare_data()
        
        # Build the model
        model = Sequential([
            Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
        
        # Compile the model
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        
        # Train the model
        history = model.fit(
            X_train, y_train,
            epochs=20,
            batch_size=32,
            validation_data=(X_test, y_test),
            verbose=1
        )
        
        # Evaluate the model
        loss, accuracy = model.evaluate(X_test, y_test)
        print(f"Neural network accuracy: {accuracy:.4f}")
        
        # Save the model
        model.save('models/url_neural_network.keras')
        
        print("URL phishing detection neural network saved to models/url_neural_network")
        
        # For compatibility with the existing interface, we'll also save a RandomForest model
        self.train_random_forest()
        
        return model
    
    def train_random_forest(self):
        """Train a Random Forest classifier for URL phishing detection"""
        print("Training Random Forest for URL phishing detection...")
        
        # Prepare data
        X_train, X_test, y_train, y_test = self.prepare_data()
        
        # Initialize and train Random Forest model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        
        print(f"Random Forest accuracy: {accuracy:.4f}")
        print("Classification report:")
        print(report)
        
        # Save the model
        with open('models/url_classifier.pkl', 'wb') as f:
            pickle.dump(self.model, f)
        
        print("URL phishing detection Random Forest model saved to models/url_classifier.pkl")
        
        return self.model
    
    def load_model(self):
        """Load a trained model from disk"""
        try:
            with open('models/url_classifier.pkl', 'rb') as f:
                self.model = pickle.load(f)
            print("URL phishing detection model loaded successfully")
            return True
        except Exception as e:
            print(f"Error loading URL model: {e}")
            return False


if __name__ == "__main__":
    # Train email model
    email_trainer = EmailModelTrainer()
    email_trainer.train_model()
    
    # Train URL model
    url_trainer = URLModelTrainer()
    url_trainer.train_neural_network()
    
    print("Training complete!")