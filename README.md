# Mini Flask Phishing Detector

This small Flask app provides a web form to submit a URL and runs a pickled model to predict whether the URL is phishing or legitimate.

Files you can place in this folder:
- `phishing_model.pkl` or `phishing_detector.pkl` - your trained scikit-learn-like model (must implement `predict` or `predict_proba`).
- `feature_names.pkl` - optional list of feature names (in order) used during training.
- `scaler.pkl` - optional scikit-learn scaler with `transform`.

Quick start (Windows PowerShell):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

Notes and next steps:
- The app includes a basic feature extractor for common URL features. For best results provide `feature_names.pkl` matching your model.
- For production, change the secret key, disable debug, and consider containerizing.

Smoke test (no server):

```powershell
# from the project folder, make sure your python environment is active
python -c "from importlib import import_module; m=import_module('app'); c=m.app.test_client(); r=c.get('/'); print('STATUS', r.status_code)"
```

Troubleshooting:
- If the app fails to import because your pickled model uses a different scikit-learn version, you'll see warnings or unpickle errors. Re-train or re-pickle with a compatible scikit-learn, or create a small wrapper that adapts the model.
- If your model expects a very specific feature ordering, provide `feature_names.pkl` (a pickled Python list) created at training time so the app can align features correctly.
- For Windows PowerShell, when creating a venv use `python -m venv .venv; .\.venv\Scripts\Activate.ps1` and then `pip install -r requirements.txt`.
