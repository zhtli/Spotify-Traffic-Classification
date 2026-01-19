# Offline Spotify Quality Classifier

This component implements an **offline Machine Learning–based classifier** to estimate Spotify audio quality from captured network traffic.

The classifier works on previously captured PCAP files or live traffic and predicts the streaming quality using statistical and burst-based features.

---

## Python Version

Python 3.9+ recommended

---

## System requirements

- Linux system
- Python 3.9+
- Root privileges (required for live capture)
- Captured PCAP files or active Spotify playback

---

## Dependencies

Required Python libraries:

- `scapy`
- `numpy`
- `pandas`
- `scikit-learn`
- `pickle`

Install system dependency:

```bash
sudo apt install python3-scapy
```

Install Python dependencies (inside a virtual environment if desired):

```bash
pip install numpy pandas scikit-learn
```

---

## Model file

The classifier requires a trained model file:

```text
best_model.pkl
```

If the model file is missing, you must train it first using the training script.

---

## How to run

The main script is:

```text
analyzer.py
```

---

## Analyze a PCAP file (offline)

Analyze a previously captured PCAP file:

```bash
python3 analyzer.py --pcap capture.pcap
```

---

## Analyze a directory of PCAP files

Analyze all PCAP files in a directory:

```bash
python3 analyzer.py --dir ./pcaps
```

---

## Live capture and analysis

Capture traffic in real time and analyze it:

```bash
sudo python3 analyzer.py --live -i eth0 -d 60
```

Parameters:
- `-i`: Network interface (default: eth0)
- `-d`: Capture duration in seconds

---

## Output

The script prints:

- Predicted audio quality
- Confidence score
- Per-class probabilities
- Window-based quality evolution
- Final majority-based prediction

Temporary PCAP files are saved automatically during live capture.

---

## Quality classes

The predicted quality labels depend on the trained model, typically including:

- `low`
- `normal`
- `high`
- `very_high`

---

## Notes

- Works with encrypted traffic (HTTPS)
- Does not require access to audio content
- Accuracy depends on the trained model and traffic quality
