import re
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
import pickle

# Feature extractor class
class URLFeatureExtractor:
    def extract_features(self, url):
        """Extract all 21 features from a URL"""
        features = {}

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        features['having_IPhaving_IP_Address'] = self.having_ip(domain)
        features['URLURL_Length'] = self.url_length(url)
        features['Shortining_Service'] = self.shortening_service(domain)
        features['having_At_Symbol'] = self.having_at_symbol(url)
        features['double_slash_redirecting'] = self.double_slash_redirect(url)
        features['Prefix_Suffix'] = self.prefix_suffix(domain)
        features['having_Sub_Domain'] = self.having_sub_domain(domain)
        features['Favicon'] = -1
        features['port'] = self.port(parsed)
        features['HTTPS_token'] = self.https_token(domain)
        features['Request_URL'] = -1
        features['URL_of_Anchor'] = -1
        features['Links_in_tags'] = -1
        features['SFH'] = -1
        features['Submitting_to_email'] = -1
        features['Abnormal_URL'] = -1
        features['Redirect'] = self.redirect(path)
        features['on_mouseover'] = -1
        features['RightClick'] = -1
        features['popUpWidnow'] = -1
        features['Iframe'] = -1

        return features

    def having_ip(self, domain):
        ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        return -1 if ip_pattern.search(domain) else 1

    def url_length(self, url):
        if len(url) < 54: return 1
        elif len(url) <= 75: return 0
        return -1

    def shortening_service(self, domain):
        services = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd']
        return -1 if any(s in domain for s in services) else 1

    def having_at_symbol(self, url):
        return -1 if '@' in url else 1

    def double_slash_redirect(self, url):
        return -1 if url[7:].count('//') > 0 else 1

    def prefix_suffix(self, domain):
        return -1 if '-' in domain else 1

    def having_sub_domain(self, domain):
        dots = domain.count('.')
        if dots == 1: return 1
        elif dots == 2: return 0
        return -1

    def port(self, parsed):
        return -1 if parsed.port else 1

    def https_token(self, domain):
        return -1 if 'https' in domain.lower() and 'https://' not in domain.lower() else 1

    def redirect(self, path):
        return -1 if path.count('//') > 1 else 1

# Combined phishing detector class
class PhishingDetector:
    def __init__(self, feature_extractor, feature_names, scaler, model):
        self.feature_extractor = feature_extractor
        self.feature_names = feature_names
        self.scaler = scaler
        self.model = model
    
    def predict(self, url):
        """
        Predict if a URL is a phishing site.
        Returns True for phishing, False for legitimate.
        """
        features = self.feature_extractor.extract_features(url)
        feature_array = []
        for name in self.feature_names:
            feature_array.append(features.get(name, 0))
        X = np.array([feature_array])
        X_scaled = self.scaler.transform(X)
        prediction = self.model.predict(X_scaled)[0]
        return bool(prediction == 0)  # 0 for phishing, 1 for legitimate
    
    def predict_proba(self, url):
        """
        Get prediction probabilities for a URL.
        Returns array with [legitimate_prob, phishing_prob]
        """
        features = self.feature_extractor.extract_features(url)
        feature_array = []
        for name in self.feature_names:
            feature_array.append(features.get(name, 0))
        X = np.array([feature_array])
        X_scaled = self.scaler.transform(X)
        probabilities = self.model.predict_proba(X_scaled)[0]
        return probabilities
    
    def get_features(self, url):
        """
        Extract and scale features for a URL.
        Returns raw features, scaled features, and feature names.
        """
        features = self.feature_extractor.extract_features(url)
        feature_array = []
        for name in self.feature_names:
            feature_array.append(features.get(name, 0))
        X = np.array([feature_array])
        X_scaled = self.scaler.transform(X)
        return features, X_scaled, self.feature_names

print("Loading dataset...")
df = pd.read_csv('dataset.csv')

INTERNAL_FEATURES = [
    'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service',
    'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
    'having_Sub_Domain', 'Favicon', 'port', 'HTTPS_token',
    'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
    'Submitting_to_email', 'Abnormal_URL', 'Redirect',
    'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe'
]

X = df[INTERNAL_FEATURES]
y = df['Result'].replace(-1, 0)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("Training Random Forest...")
model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
model.fit(X_train_scaled, y_train)

y_pred = model.predict(X_test_scaled)
y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

print(f"\n{'='*60}")
print(f"✅ MODEL TRAINED!")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"ROC AUC: {roc_auc_score(y_test, y_pred_proba):.4f}")
print(f"{'='*60}\n")

# Create combined detector
detector = PhishingDetector(
    feature_extractor=URLFeatureExtractor(),
    feature_names=INTERNAL_FEATURES,
    scaler=scaler,
    model=model
)

print("Testing model...")
test_urls = [
    "https://www.google.com",  # Legitimate
    "http://192.168.1.1/fake",  # Has IP address
    "http://bit.ly/suspicious",  # URL shortener
    "https://paypal-verify@malicious.com"  # Has @ symbol
]

for url in test_urls:
    is_phishing = detector.predict(url)
    proba = detector.predict_proba(url)
    print(f"\nURL: {url}")
    print(f"Prediction: {'PHISHING' if is_phishing else 'LEGITIMATE'}")
    print(f"Probabilities: {proba.round(3)}")
    
    # Print key features for phishing prediction
    raw_features, scaled_features, feature_names = detector.get_features(url)
    print("\nKey Features:")
    for name, value in raw_features.items():
        if value == -1:  # Only show features that indicate phishing
            print(f"- {name}: {value}")

print("\nSaving model components...")

# Save individual components
with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
with open('feature_names.pkl', 'wb') as f:
    pickle.dump(INTERNAL_FEATURES, f)

# Save combined detector
with open('phishing_detector.pkl', 'wb') as f:
    pickle.dump(detector, f)

print("✅ All model files saved!")