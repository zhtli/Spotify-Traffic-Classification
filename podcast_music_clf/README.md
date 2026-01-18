#  Spotify Encrypted Traffic Classification using Machine Learning

This tool captures **live network traffic**, extracts statistical and burst-based features, and uses **trained ML models** to classify Spotify traffic as **Music or Podcast**, and predict the **music genre** when applicable.

It also generates a **packet timeline visualization** with peak detection.

---

##  Project Structure

```
podcast_music_clf/
├── live_predict.py
├── train_models.py
├── models/
│   ├── content_type_rf.pkl
│   ├── genre_xgboost.pkl
│   ├── genre_label_encoder.pkl
│   ├── content_lasso_features.pkl
│   └── genre_lasso_features.pkl
├── dataset/
|   └── dataset files (spotify_features.csv)
├── pcap/
│   └── (optional training pcaps)
└── README.md
```

---

## Prerequisites

### Python Version

* **Python 3.9+** recommended

### Install Dependencies

Create and activate a virtual environment, then install requirements:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Required libraries include:

* `scapy`
* `numpy`
* `pandas`
* `scikit-learn`
* `xgboost`
* `matplotlib`
* `scipy`
* `joblib`

---

## Model Training

Pre-trained models are already included in the models/ directory, so you do NOT need to train the models to run live prediction.

## When do you need to retrain?

* You only need to retrain the models if:
* You add a new dataset
* You modify feature extraction or labels
* You want to improve or update model performance

## Retraining Command
python train_models.py

This will overwrite/update the files inside the models/ directory.

**Note:** If models are missing or incompatible, the live analyzer will fail with:

Make sure you've run train.py first!
---

##  Configure Network Interface

Edit this line in `live_predict.py` if needed:

```python
INTERFACE = "enp0s3"
```

Common interface names:

* Linux: `eth0`, `wlan0`, `enp0s3`
* macOS: `en0`
* VM users: check with `ip a` or `ifconfig`

---

##  Run Live Traffic Analysis

You **must run with root/admin privileges** to capture packets.

```bash
sudo python live_predict.py
```

What happens:

1. Captures **60 seconds** of live traffic
2. Saves packets to `live_capture.pcap`
3. Extracts statistical & burst features
4. Predicts:

   * **Content Type**: Music / Podcast
   * **Genre** (if Music)
5. Generates:

   * `packet_timeline.png`

---
