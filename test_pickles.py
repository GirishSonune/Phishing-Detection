import pickle
from pathlib import Path

def try_load_pickle(filepath):
    print(f"Testing {filepath}...")
    try:
        if not Path(filepath).exists():
            print(f"✗ File not found: {filepath}")
            return None
            
        with open(filepath, 'rb') as f:
            obj = pickle.load(f)
            print(f"✓ Successfully loaded {filepath}")
            print(f"Object type: {type(obj)}")
            print(f"Object content: {obj}")
            return obj
    except Exception as e:
        print(f"✗ Error loading {filepath}: {str(e)}")
        return None

# Test each pickle file
model = try_load_pickle('phishing_model.pkl')
print()
features = try_load_pickle('feature_names.pkl')
print()
scaler = try_load_pickle('scaler.pkl')
print()
detector = try_load_pickle('phishing_detector.pkl')