# feature_extractor.py
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from urllib.parse import urlparse
import ipaddress

class EnhancedFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts a comprehensive set of structural and keyword-based features from URLs."""

    def __init__(self):
        # A list of common URL shortening services
        self.shorteners = [
            'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'cutt.ly', 'is.gd',
            'cli.gs', 'me2.kr', 'reurl.cc', 'han.gl', 'j.mp', 'zpr.io'
        ]
        # Keywords commonly found in phishing URLs
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'secure', 'paypal', 'bank', 'free',
            'gift', 'claim', 'update', 'signin', 'password', 'admin', 'icloud',
            'apple', 'ebay', 'amazon', 'microsoft', 'wallet', 'support'
        ]

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        feature_list = []
        for url in X:
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.hostname if parsed_url.hostname else ''
            except Exception:
                domain = ''
                parsed_url = None

            # --- Start Feature Extraction ---
            # 1. URL Length > 75
            is_long_url = 1 if len(url) > 75 else 0
            # 2. Presence of '@' symbol
            has_at = 1 if '@' in url else 0
            # 3. Presence of '-' in the domain
            has_dash_in_domain = 1 if domain and '-' in domain else 0
            # 4. Check if the domain is a shortening service
            is_shortened = 1 if any(shortener == domain for shortener in self.shorteners) else 0
            # 5. Check for '//' in the URL path (redirection)
            has_double_slash = 1 if parsed_url and '//' in parsed_url.path else 0
            # 6. Count of suspicious keywords in the whole URL
            keyword_count = sum([1 for keyword in self.suspicious_keywords if keyword in url.lower()])
            # 7. Check if domain is an IP address
            has_ip_in_domain = 0
            try:
                if domain:
                    ipaddress.ip_address(domain)
                    has_ip_in_domain = 1
            except ValueError:
                pass
            # 8. Count number of dots
            dot_count = url.count('.')

            feature_list.append([
                is_long_url, has_at, has_dash_in_domain, is_shortened,
                has_double_slash, keyword_count, has_ip_in_domain, dot_count
            ])

        return np.array(feature_list)