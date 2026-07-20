from flask import Flask, render_template, jsonify, request
import pandas as pd
import numpy as np
import os
from main import CybersecurityThreatDetector, generate_sample_network_data

app = Flask(__name__)
detector = CybersecurityThreatDetector()

# Check if models exist, otherwise train them
models_dir = "./models"
required_models = [
    "network_autoencoder.pkl",
    "network_isoforest.pkl",
    "network_scaler.pkl",
    "network_threshold.pkl",
    "network_feature_cols.pkl",
    "malware_detector.pkl",
    "phishing_vectorizer.pkl",
    "phishing_detector.pkl"
]
models_exist = all(os.path.exists(os.path.join(models_dir, m)) for m in required_models)

if models_exist:
    print("Loading existing models...")
    detector.load_models(models_dir)
else:
    print("Models missing. Training models from scratch...")
    detector.train()
    detector.save_models(models_dir)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    return jsonify({
        'network': {
            'threshold': float(detector.network_threshold) if detector.network_threshold is not None else 0.0,
            'features_count': len(detector.network_feature_cols) if detector.network_feature_cols is not None else 0
        },
        'malware': {
            'estimators': len(detector.malware_detector.estimators_) if detector.malware_detector is not None else 0,
            'features': list(detector.malware_detector.feature_names_in_) if detector.malware_detector is not None else []
        },
        'phishing': {
            'vocabulary_size': len(detector.phishing_vectorizer.vocabulary_) if detector.phishing_vectorizer is not None else 0
        }
    })

@app.route('/api/detect/network', methods=['POST'])
def detect_network():
    data = request.json
    try:
        df = pd.DataFrame(data)
        results = detector.detect_network_threats(df)
        anomalies = [bool(a) for a in results['anomalies']]
        scores = [float(s) for s in results['scores']]
        return jsonify({
            'anomalies': anomalies,
            'scores': scores,
            'num_anomalies': int(results['num_anomalies']),
            'anomaly_percentage': float(results['anomaly_percentage'])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/detect/malware', methods=['POST'])
def detect_malware_api():
    data = request.json
    try:
        if 'features' in data:
            features = data['features']
            features_df = pd.DataFrame([features])
            if hasattr(detector.malware_detector, 'feature_names_in_'):
                features_df = features_df[detector.malware_detector.feature_names_in_]
            malware_prob = float(detector.malware_detector.predict_proba(features_df)[0, 1])
            is_malware = bool(malware_prob > 0.5)
            return jsonify({
                'is_malware': is_malware,
                'malware_probability': malware_prob
            })
        elif 'file_path' in data:
            results = detector.detect_malware([data['file_path']])
            res = results[0]
            if 'error' in res:
                return jsonify({'error': res['error']}), 400
            return jsonify({
                'file_path': res['file_path'],
                'is_malware': bool(res['is_malware']),
                'malware_probability': float(res['malware_probability']),
                'features': res['features']
            })
        else:
            return jsonify({'error': 'No input provided'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/detect/phishing', methods=['POST'])
def detect_phishing_api():
    data = request.json
    if not data or 'email' not in data:
        return jsonify({'error': 'No email content provided'}), 400
    try:
        email = data['email']
        results = detector.detect_phishing([email])
        res = results[0]
        if 'error' in res:
            return jsonify({'error': res['error']}), 400
        return jsonify({
            'is_phishing': bool(res['is_phishing']),
            'phishing_probability': float(res['phishing_probability']),
            'features': {k: bool(v) if isinstance(v, (bool, np.bool_)) else int(v) for k, v in res['features'].items()}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/simulate/network', methods=['GET'])
def simulate_network():
    df = generate_sample_network_data(15)
    packets = df.to_dict(orient='records')
    results = detector.detect_network_threats(df)
    anomalies = [bool(a) for a in results['anomalies']]
    scores = [float(s) for s in results['scores']]
    for i, p in enumerate(packets):
        p['is_anomaly'] = anomalies[i]
        p['anomaly_score'] = scores[i]
    return jsonify(packets)

if __name__ == '__main__':
    # Only open browser once when Flask reloader is active
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        import webbrowser
        from threading import Timer
        Timer(1, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    
    app.run(host='0.0.0.0', port=5000, debug=True)

