import pickle
import numpy as np
from urllib.parse import urlparse
import re

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

print("Loading models...")

# Try loading model components
try:
    with open('phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("✓ Loaded phishing_model.pkl")
except Exception as e:
    print(f"✗ Error loading phishing_model.pkl: {e}")
    model = None

try:
    with open('feature_names.pkl', 'rb') as f:
        feature_names = pickle.load(f)
    print("✓ Loaded feature_names.pkl")
    print(f"Feature names: {feature_names}")
except Exception as e:
    print(f"✗ Error loading feature_names.pkl: {e}")
    feature_names = None

try:
    with open('scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
    print("✓ Loaded scaler.pkl")
except Exception as e:
    print(f"✗ Error loading scaler.pkl: {e}")
    scaler = None

try:
    with open('phishing_detector.pkl', 'rb') as f:
        detector = pickle.load(f)
    print("✓ Loaded phishing_detector.pkl")
except Exception as e:
    print(f"✗ Error loading phishing_detector.pkl: {e}")
    detector = None

# Test URLs to try
test_urls = [
    "https://www.google.com",  # Legitimate
    "http://192.168.1.1/fake",  # Has IP address
    "http://bit.ly/suspicious",  # URL shortener
    "https://paypal-verify@malicious.com"  # Has @ symbol
]

print("\nTesting URLs:")
print("-" * 50)

for test_url in test_urls:
    print(f"\nTesting URL: {test_url}")
    print("-" * 30)

    # First try the combined detector
    if detector is not None:
        try:
            print("\nUsing phishing_detector.pkl:")
            is_phishing = detector.predict(test_url)
            proba = detector.predict_proba(test_url)
            print(f"Prediction: {'PHISHING' if is_phishing else 'LEGITIMATE'}")
            print(f"Probabilities: {proba.round(3)}")
        except Exception as e:
            print(f"Error using detector: {e}")

    # Then try the separate components
    if all([model, feature_names, scaler]):
        try:
            print("\nUsing separate components:")
            # Extract features
            extractor = URLFeatureExtractor()
            features = extractor.extract_features(test_url)
            print("\nExtracted features:")
            for name, value in features.items():
                print(f"{name}: {value}")
            
            # Convert to array
            feature_array = []
            for name in feature_names:
                feature_array.append(features.get(name, 0))
            X = np.array([feature_array])
            
            # Scale
            X_scaled = scaler.transform(X)
            
            # Predict
            prediction = model.predict(X_scaled)[0]
            probabilities = model.predict_proba(X_scaled)[0]
            print(f"\nPrediction: {'PHISHING' if prediction == 0 else 'LEGITIMATE'}")
            print(f"Probabilities (Phishing, Legitimate): {probabilities.round(3)}")
        except Exception as e:
            print(f"Error using separate components: {e}")
    
    print("-" * 50)