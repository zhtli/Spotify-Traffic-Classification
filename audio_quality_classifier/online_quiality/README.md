# Spotify Audio Quality Classification

This project provides two approaches for Spotify audio quality classification:
- Machine Learning–based method
- Traffic-based analysis method

This README describes the requirements and usage of the traffic-based approach.

---

## Python Version

Python 3.9+ recommended

---

## System requirements

- Linux system
- Root privileges (required for packet capture)
- Active internet connection
- Spotify Web Player or Spotify Desktop

---

## Dependencies

The traffic-based method requires the following Python library:

- `scapy`

Install it using:

```bash
sudo apt install python3-scapy
```

---

## Setup virtual environment (optional)

Create and activate a virtual environment inside this folder:

```bash
cd online_quality
python3 -m venv venv
source venv/bin/activate
pip install scapy
```

---

## How to run (traffic-based method)

The main script is:

```text
spotify_capture_v2.py
```

---

## Scan Spotify IPs (first run)

Detect Spotify-related IPs and store them persistently.

```bash
sudo python3 spotify_capture_v2.py --scan
```

While scanning:
- Open Spotify
- Play any song
- Wait until the scan finishes

---

## Capture traffic and estimate quality

Uses stored IPs to capture Spotify traffic and estimate audio quality.

```bash
sudo python3 spotify_capture_v2.py -i eth0 -d 60
```

---

## Scan and capture in one step

```bash
sudo python3 spotify_capture_v2.py -i eth0 -d 60 --scan-first
```

---

## List stored Spotify IPs

```bash
python3 spotify_capture_v2.py --list
```

---

## Clear stored IPs

```bash
python3 spotify_capture_v2.py --clear
```

---

## Output

A JSON file is generated in the `captures/` directory containing:
- Capture metadata
- Estimated bitrate
- Estimated audio quality
- Active Spotify IPs
- Per-packet traffic data

---

## Quality levels

- `low`
- `normal`
- `high`
- `high_premium`
- `very_high`

---

## Notes

- Works with encrypted traffic (HTTPS)
- No modification of the Spotify application is required
