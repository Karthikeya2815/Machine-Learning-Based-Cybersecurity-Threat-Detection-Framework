# 🛡️ Machine Learning-Based Cybersecurity Threat Detection Framework

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?logo=scikitlearn&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-Unlicensed-lightgrey)

A machine learning-based cybersecurity framework that detects threats across **three critical domains** — network anomalies, malware, and phishing emails — using classical ML techniques including Isolation Forest, Random Forest, and an MLP-based autoencoder. Designed as a modular, extensible system, it demonstrates how multiple detection strategies can work together within a single, cohesive threat detection pipeline.

> 💡 Built as a hands-on project to apply core machine learning concepts (anomaly detection, classification, and NLP) to real-world cybersecurity problems.

---

## 📌 Overview

| Domain | Technique Used | What It Detects |
|---|---|---|
| **Network Traffic** | MLP Autoencoder + Isolation Forest | Unusual traffic patterns / intrusions |
| **Malware** | Random Forest | Malicious vs. benign executable files |
| **Phishing Emails** | TF-IDF + Random Forest | Suspicious or fraudulent email content |

---

## ✨ Key Features

- 🌐 **Network Anomaly Detection** — Identifies abnormal traffic using an autoencoder combined with Isolation Forest
- 🦠 **Malware Detection** — Classifies executables as benign or malicious using simulated PE file attributes
- 📧 **Phishing Detection** — Flags phishing emails through TF-IDF text analysis and Random Forest classification
- 🧪 **Synthetic Data Generation** — Produces realistic, reproducible datasets for safe testing and demonstration
- 💾 **Model Persistence** — Saves trained models for instant reuse without retraining

---

## 🛠️ Tech Stack

- **Language:** Python 3.8+
- **Libraries:** scikit-learn, NumPy, Pandas, Joblib
- **ML Techniques:** Isolation Forest, Random Forest, MLP Autoencoder, TF-IDF Vectorization

---

## ⚙️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/Karthikeya2815/Machine-Learning-Based-Cybersecurity-Threat-Detection-Framework.git
cd Machine-Learning-Based-Cybersecurity-Threat-Detection-Framework

# 2. (Optional) Set up a virtual environment
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

**`requirements.txt`**
```
numpy>=1.24.0
pandas>=2.0.0
scikit-learn>=1.3.0
joblib>=1.2.0
```

---

## 🚀 Usage

Run the main script to train, test, and save all models:

```bash
python main.py
```

This will:
1. Train all models on synthetic data
2. Test them on sample network traffic, malware files, and phishing emails
3. Save trained models to the `./models` directory

<details>
<summary><strong>📄 Click to see expected output</strong></summary>

```
Training Cybersecurity Threat Detection System...
1. Training Network Anomaly Detection Models...
2. Training Malware Detection Model...
3. Training Phishing Detection Model...

All models trained successfully!

===== TESTING THREAT DETECTION SYSTEM =====

1. Testing Network Anomaly Detection...
Network traffic analysis:
  - Total traffic flows: 1000
  - Detected anomalies: <number>
  - Anomaly percentage: <percentage>%

2. Testing Malware Detection...
Malware detection results:
  - benign_test_1.exe: <BENIGN/MALWARE> (confidence: <percentage>%)
  - malware_test_1.exe: <BENIGN/MALWARE> (confidence: <percentage>%)
  - suspicious_file.exe: <BENIGN/MALWARE> (confidence: <percentage>%)

3. Testing Phishing Detection...
Phishing detection results:
  - Email 1: <LEGITIMATE/PHISHING> (confidence: <percentage>%)
  - Email 2: <LEGITIMATE/PHISHING> (confidence: <percentage>%)
  - Email 3: <LEGITIMATE/PHISHING> (confidence: <percentage>%)

All models saved to ./models
===== SYSTEM READY FOR DEPLOYMENT =====
```
</details>

### Custom Usage
- To use real-world data, modify `main.py` and adjust the input passed to the `detector.detect_*` methods.
- To skip retraining, load saved models with `detector.load_models()` and run predictions directly.

---

## 📁 Project Structure

```
Machine-Learning-Based-Cybersecurity-Threat-Detection-Framework/
├── main.py              # Main script with all functionality
├── models/              # Directory for saved models (created after running)
│   ├── network_autoencoder.pkl
│   ├── network_isoforest.pkl
│   ├── network_scaler.pkl
│   ├── malware_detector.pkl
│   ├── phishing_vectorizer.pkl
│   └── phishing_detector.pkl
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

---

## 🔍 How It Works

**Network Anomaly Detection**
Combines an `MLPRegressor`-based autoencoder with Isolation Forest to flag anomalies using features like bytes sent/received, connection duration, port, protocol type, service, and flag.

**Malware Detection**
A Random Forest classifier trained on simulated PE file features (file size, entropy, imports) to distinguish malicious files (`1`) from benign ones (`0`).

**Phishing Detection**
TF-IDF vectorization paired with Random Forest to catch suspicious email patterns — urgent language, misspellings, and other red flags common in phishing attempts.

**Synthetic Data**
All models are trained and tested on synthetic, reproducible data — generated with fixed seeds to simulate realistic conditions without requiring sensitive real-world datasets.

---

## 🎯 What This Project Demonstrates

- Practical application of **supervised and unsupervised ML** techniques to cybersecurity
- Experience with **model persistence, evaluation, and deployment-readiness**
- Ability to design **modular, extensible software** around multiple ML pipelines
- Understanding of **feature engineering** across structured (network/malware) and unstructured (text) data

---

## 🤝 Contributing

Contributions are welcome! Feel free to fork this repository, submit pull requests, or open issues for bugs and feature suggestions.

---

## 📄 License

This project is unlicensed — free to use for educational or personal purposes. For commercial use, please reach out to the author.

---

## 👤 Author

**G.Karthikeya**
GitHub: Karthikeya2815
AI/ML Student | AI/ML Enthusiast


