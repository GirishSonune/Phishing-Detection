import sys
import traceback

sys.path.append(r"C:\Users\giris\Downloads\Deply Phishing")

try:
    import app as appmod
    app = appmod.app
    client = app.test_client()
    res = client.get('/')
    print('STATUS', res.status_code)
except Exception as e:
    traceback.print_exc()
    print('ERROR', e)
