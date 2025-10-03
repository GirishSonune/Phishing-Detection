# train_model.py
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# Import our new, smarter feature extractor
from feature_extractor import EnhancedFeatureExtractor

print("Loading and preparing data...")

legit_df = pd.read_csv("extracted_legitmate_dataset.csv")
phish_df = pd.read_csv("extracted_phishing_dataset.csv")

legit_df['url'] = legit_df['protocol'].fillna('') + '://' + legit_df['domain_name'].fillna('')
phish_df['url'] = phish_df['protocol'].fillna('') + '://' + phish_df['domain_name'].fillna('')
df = pd.concat([legit_df[['url', 'label']], phish_df[['url', 'label']]], ignore_index=True)
df.dropna(subset=['url', 'label'], inplace=True)

X = df['url']
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# The pipeline combines lexical analysis with our new enhanced manual features
enhanced_pipeline = Pipeline([
    ('features', FeatureUnion([
        ('lexical', TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 6))),
        ('manual', EnhancedFeatureExtractor())
    ])),
    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
])

print("Training the enhanced model...")
enhanced_pipeline.fit(X_train, y_train)

accuracy = enhanced_pipeline.score(X_test, y_test)
print(f"Enhanced Model Accuracy on Test Set: {accuracy:.4f}")

print("Saving the model to 'phishing_detector.joblib'...")
joblib.dump(enhanced_pipeline, "phishing_detector.joblib")

print("✅ Model training complete and saved successfully!")