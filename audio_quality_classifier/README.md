## Audio quality classification

In this folder, we provide two different approaches for **Spotify audio quality classification**:

- A **Machine Learning–based** method
- A **traffic-based analysis** method

Both approaches estimate audio quality **without accessing the audio content itself**.

---

## Online quality (traffic-based)

The `online_quality` folder contains a method that estimates Spotify audio quality by **analyzing network traffic in real time**.

This approach:
- Identifies Spotify-related IP addresses (DNS + CDN traffic)
- Captures only traffic associated with those IPs
- Estimates the effective bitrate from incoming audio packets
- Classifies audio quality based on bitrate ranges

---

## Offline classifier (Machine Learning)

The `offline_classifier` folder contains the **Machine Learning model and analysis scripts** used to classify Spotify audio quality.

This approach is based on **statistical and burst-based features** extracted from network traffic and supports **both offline and online analysis modes**.

### Capabilities

- **Offline analysis**:
  - Analyze previously captured `.pcap` files
  - Analyze entire directories of PCAPs
- **Online analysis**:
  - Capture live traffic and classify quality in real time

### Model

- Trained using an **XGBoost classifier**
- Uses sliding time windows to extract features
- Handles class imbalance using **SMOTE and data augmentation**
- Model, scaler, label encoder, and feature list are stored in:

```text
best_model.pkl
```

### Training overview

- Features extracted from packet sizes and inter-arrival times
- Burst detection and entropy-based features included
- Multi-class classification (`normal`, `high`, `very_high`)
- Additional binary classification (`normal` vs `high_quality`)
- Cross-validation and performance metrics are generated
- Training produces figures for analysis and reporting

---

## Quality levels

Depending on the method, the following quality labels are used:

- `low`
- `normal`
- `high`
- `high_premium`
- `very_high`

---

## Notes

- Both methods work with encrypted traffic (HTTPS)
- No interaction with the Spotify application is required
- The ML model accuracy depends on the quality and diversity of the training PCAPs
