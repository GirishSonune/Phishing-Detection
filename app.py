# app.py
from flask import Flask, render_template, request
import joblib
import os

# Import the new class so joblib can understand the saved model object
from feature_extractor import EnhancedFeatureExtractor

app = Flask(__name__)

model_path = "phishing_detector.joblib"
if not os.path.exists(model_path):
    raise FileNotFoundError("Model file 'phishing_detector.joblib' not found. Please run train_model.py first.")
    
model = joblib.load(model_path)

@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            try:
                result = model.predict([url])[0]
                prediction = "🔴 Phishing" if result == 1 else "🟢 Legitimate"
            except Exception as e:
                prediction = f"Error processing URL: {e}"
        else:
            prediction = "Please enter a URL."
            
    return render_template("index.html", prediction=prediction, url=url)

if __name__ == "__main__":
    app.run(debug=True)