# train_full_features_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np

print("Loading datasets...")

# Load legitimate and phishing datasets
try:
    legit_df = pd.read_csv("extracted_legitmate_dataset.csv")
    phish_df = pd.read_csv("extracted_phishing_dataset.csv")
except FileNotFoundError as e:
    print(f"Error loading dataset: {e}")
    print("Please make sure both 'extracted_legitmate_dataset.csv' and 'extracted_phishing_dataset.csv' are present.")
    exit()

# The 'label' column already exists, so we can merge directly
print("Merging dataframes...")
df = pd.concat([legit_df, phish_df], ignore_index=True)

# Feature Engineering: Create a single 'full_url' column for text analysis
df['full_url'] = df['protocol'].fillna('') + '://' + df['domain_name'].fillna('') + '/' + df['address'].fillna('')

# Drop original text columns and any rows with missing labels
df = df.drop(columns=['protocol', 'domain_name', 'address'])
df.dropna(subset=['label'], inplace=True)

# Define features (X) and target (y)
X = df.drop('label', axis=1)
y = df['label']

# Identify feature types for preprocessing
# We will vectorize the 'full_url' and scale the rest of the numeric features
text_feature = 'full_url'
numeric_features = [col for col in X.columns if col != text_feature and pd.api.types.is_numeric_dtype(X[col])]

print(f"Identified {len(numeric_features)} numerical features: {numeric_features}")
print(f"Identified 1 text feature: {text_feature}")

# Create a preprocessor using ColumnTransformer
# This applies different transformations to different columns
preprocessor = ColumnTransformer(
    transformers=[
        ('text', TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 6)), text_feature),
        ('numeric', StandardScaler(), numeric_features)
    ],
    remainder='passthrough' # Keep other columns if any (none in this case)
)

# Create the full machine learning pipeline
pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
])

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"Training model with {X_train.shape[1]} features on {X_train.shape[0]} samples...")
pipeline.fit(X_train, y_train)

# Evaluate the model
accuracy = pipeline.score(X_test, y_test)
print(f"Model Accuracy on Test Set: {accuracy:.4f}")

# Save the trained model
print("Saving the trained model to 'phishing_detector_full_features.joblib'...")
joblib.dump(pipeline, "phishing_detector_full_features.joblib")

print("✅ Model training complete and saved successfully!")