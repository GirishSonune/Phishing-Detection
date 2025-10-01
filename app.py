import os
import pickle
import re
from urllib.parse import urlparse
from typing import List, Dict

import numpy as np
from flask import Flask, render_template, request, jsonify


APP_DIR = os.path.dirname(os.path.abspath(__file__))


def try_load_pickle(paths: List[str]):
    for p in paths:
        abs_p = os.path.join(APP_DIR, p)
        if os.path.exists(abs_p):
            try:
                with open(abs_p, 'rb') as f:
                    return pickle.load(f), abs_p
            except Exception:
                continue
    return None, None


def load_artifacts():
    # Prefer a combined detector (phishing_detector.pkl) saved by the notebook,
    # which may implement predict/predict_proba that accept an URL directly.
    detector, det_path = try_load_pickle(['phishing_detector.pkl'])

    if detector is not None:
        # If we found a combined detector, use it as the MODEL and leave feature names/scaler None
        return detector, det_path, None, None

    # Otherwise try separate artifacts (model, feature_names, scaler)
    model, model_path = try_load_pickle(['phishing_model.pkl', 'phishing_detector.pkl', 'phishing_ model.pkl', 'phishing-model.pkl'])
    feature_names, fn_path = try_load_pickle(['feature_names.pkl'])
    scaler, sc_path = try_load_pickle(['scaler.pkl'])
    return model, model_path, feature_names, scaler


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

def extract_simple_features(url):
    extractor = URLFeatureExtractor()
    return extractor.extract_features(url)


def extract_features_for_model(url: str, feature_names: List[str]) -> np.ndarray:
    """
    Extract features using the same extractor used during training.
    """
    features = extract_simple_features(url)
    
    # Convert features to array in the exact order expected by the model
    vec = []
    for name in feature_names:
        vec.append(float(features.get(name, 0.0)))  # Use 0.0 as fallback
    
    return np.array([vec], dtype=float)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-me-for-prod'


MODEL, MODEL_PATH, FEATURE_NAMES, SCALER = load_artifacts()


@app.route('/debug/<path:test_url>')
def debug(test_url):
    """Debug endpoint to see extracted features"""
    if not test_url.startswith(('http://', 'https://')):
        test_url = 'http://' + test_url
        
    features = extract_simple_features(test_url)
    if FEATURE_NAMES:
        features_array = extract_features_for_model(test_url, FEATURE_NAMES)
        features_scaled = SCALER.transform(features_array) if SCALER else features_array
        prediction = MODEL.predict(features_scaled)[0]
        proba = MODEL.predict_proba(features_scaled)[0] if hasattr(MODEL, 'predict_proba') else None
    else:
        prediction = None
        proba = None
        
    return {
        'url': test_url,
        'raw_features': features,
        'prediction': int(prediction) if prediction is not None else None,
        'probabilities': proba.tolist() if proba is not None else None,
        'feature_names': FEATURE_NAMES,
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    details = None
    used_model = MODEL_PATH
    error = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            error = 'Please provide a URL.'
            return render_template('index.html', error=error)

        if MODEL is None:
            error = 'No model found in the application directory. Place your pickled model as `phishing_model.pkl` or `phishing_detector.pkl`.'
            return render_template('index.html', error=error)

        # build feature vector
        if FEATURE_NAMES is not None and isinstance(FEATURE_NAMES, (list, tuple)) and len(FEATURE_NAMES) > 0:
            X = extract_features_for_model(url, FEATURE_NAMES)
        else:
            # if we don't have feature names, compute a short vector with a stable ordering
            fallback_names = ['url_length', 'num_dots', 'num_hyphens', 'num_digits', 'has_ip', 'num_subdomains']
            X = extract_features_for_model(url, fallback_names)

        # apply scaler if available
        try:
            if SCALER is not None:
                X = SCALER.transform(X)
        except Exception:
            # ignore scaler errors but note them
            pass

        # predict
        try:
            if hasattr(MODEL, 'predict_proba'):
                proba = MODEL.predict_proba(X)
                # assume class 1 is malicious if present
                if proba.shape[1] == 2:
                    score = float(proba[0, 1])
                else:
                    # fallback: take max probability
                    score = float(np.max(proba))
                pred = 1 if score >= 0.5 else 0
            else:
                pred = int(MODEL.predict(X)[0])
                score = None

            label = 'malicious' if int(pred) == 1 else 'legitimate'
            result = {'label': label, 'probability': score}
            details = {'url': url}
        except Exception as e:
            error = f'Error running model prediction: {e}'

    return render_template('index.html', result=result, details=details, model_path=used_model, error=error)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
