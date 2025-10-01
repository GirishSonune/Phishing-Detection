import re
from urllib.parse import urlparse

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

def print_features(url):
    """Extract and print features for a URL"""
    print(f"\nAnalyzing URL: {url}")
    print("-" * 50)
    
    extractor = URLFeatureExtractor()
    features = extractor.extract_features(url)
    
    # Count phishing indicators
    phishing_features = [name for name, value in features.items() if value == -1]
    
    print("\nFeature Analysis:")
    for name, value in sorted(features.items()):
        indicator = "⚠️ Phishing indicator" if value == -1 else "✓ Normal"
        print(f"{name:30} = {value:2} | {indicator}")
        
    print(f"\nSummary:")
    print(f"Total features: {len(features)}")
    print(f"Phishing indicators found: {len(phishing_features)}")
    if phishing_features:
        print("\nPhishing indicators present:")
        for feature in phishing_features:
            print(f"- {feature}")

if __name__ == '__main__':
    test_urls = [
        "https://www.google.com",  # Legitimate
        "http://192.168.1.1/fake",  # Has IP address
        "http://bit.ly/suspicious",  # URL shortener
        "https://paypal-verify@malicious.com",  # Has @ symbol
        "https://mybank-secure.com/login",  # Has hyphen
        "http://user:pass@fake.com",  # Has credentials
        "http://sub1.sub2.sub3.domain.com"  # Multiple subdomains
    ]
    
    for url in test_urls:
        print_features(url)