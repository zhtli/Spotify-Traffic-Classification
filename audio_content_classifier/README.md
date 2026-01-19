# Spotify Encrypted Traffic - Audio Content Identification

This module captures **live encrypted Spotify traffic**, extracts statistical and burst-based features, and uses a trained Machine Learning model to **identify the audio content currently playing**.

It is designed to integrate into the overall **Spotify Traffic Classification** project and focuses specifically on **title-level content identification**.

---

## Project Structure

```
audio_content_classifier/
├── README.md
├── capture_config.json
├── capture_single_spotify_flow.py
├── extract_features.py
├── gb_final_v2.joblib
├── gradient_boosting_holdout.py
├── predict.py
├── realtime_pipeline.py
└── show_prediction.py
```

---

## Pipeline scripts

- `realtime_pipeline.py`: Runs the full real-time pipeline (capture → feature extraction → prediction → show result).
- `capture_single_spotify_flow.py`: Captures live Spotify encrypted traffic and saves it for analysis.
- `extract_features.py`: Extracts statistical and burst-based features from captured traffic.
- `predict.py`: Loads the trained model and predicts the currently playing content title.
- `show_prediction.py`: Displays the final predicted content title in a readable format.
- `gb_final_v2.joblib`: Pre-trained ML model used for inference.
- `gradient_boosting_holdout.py`: Script to train and evaluate a Gradient Boosting model using a holdout validation split.
- `capture_config.json`: Configuration file for capture parameters (interface, duration, filters, etc.).

---

## Prerequisites

### Python Version

- **Python 3.9+** recommended

### Install dependencies

From the root of the repository:

```bash
pip install -r requirements.txt
```

### Setup virtual environment

Create and activate a virtual environment inside this folder:

```bash
cd audio_content_classifier
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt
```

### How to run (real-time pipeline)

The main script is

- `realtime_pipeline.py`

It automatically runs the full pipeline:

1. Capture Spotify traffic
2. Extract features
3. Predict the content title
4. Display final prediction

To executed:

```bash
cd audio_content_classifier
python realtime_pipeline.py
```

## Output

At the end of the execution, the pipeline prints the **final predicted content title** in the terminal.
During execution, the prediction is also saved into:

```md
-`predictions.csv`
```
