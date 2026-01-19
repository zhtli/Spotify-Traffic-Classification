## Audio quality classification

In this folder, we provide two different approaches for **Spotify audio quality classification**:

- A **Machine Learning–based** method
- A **traffic-based analysis** method

Both approaches aim to estimate the audio quality without accessing the audio content itself.

## Online quality (traffic-based)

The `online_quality` folder contains a method that estimates Spotify audio quality by **analyzing network traffic in real time**.

This approach works by identifying Spotify-related IP addresses and analyzing the incoming traffic associated with them.

## How it works

- Detects Spotify IPs using:
  - DNS responses for Spotify domains
  - HTTPS traffic patterns to known CDN ranges (Akamai / Fastly)
- Stores detected IPs persistently for reuse across executions
- Captures only traffic associated with known Spotify IPs
- Filters incoming packets to isolate audio traffic
- Estimates the effective bitrate from received audio packets
- Classifies audio quality based on the measured bitrate

## Quality levels

- `low`
- `normal`
- `high`
- `high_premium`
- `very_high`

## Output

The script generates a JSON file containing:

- Capture metadata
- Estimated bitrate
- Estimated audio quality
- Active Spotify IPs
- Per-packet traffic data

## Notes

- Requires root privileges
- Works with encrypted traffic (HTTPS)
- No interaction with the Spotify application is required
