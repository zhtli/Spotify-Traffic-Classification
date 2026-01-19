# Spotify Traffic Classification

In this project we analyze and classify Spotify encrypted traffic to try to recognize characteristics of the content being streamed. We trained ML model to learn Spotify's streaming pattern and classify it in different categories, e.g. Music or Podcast, or the audio quality setting.

Each folder and model in this repository includes its own dedicated README with detailed usage instructions, configuration steps, and explanations.

## Data Capture Process

Inside the folder `spotify_data_capture_process` you will find the script used to capture data from an interface while running spotify.

## Classifiers

## Audio quality classification

This folder contains two approaches for Spotify audio quality classification: a traffic-based method and a Machine Learning–based method.

The `online_quality` approach estimates audio quality in real time by analyzing encrypted network traffic and bitrate.

The `offline_classifier` folder contains a trained Machine Learning model that extracts statistical and burst-based features from traffic.

The ML approach supports both **offline analysis of PCAP files** and **online live traffic classification**.

### Content Type Classifier

Inside the folder `podcast_music_clf`you will find the code and models to classify Spotify streams as Music or Podcast. The classifier analyzes network traffic patterns—such as packet timing, size, and burstiness—without accessing the actual audio content.

### Audio Content Classifier

Inside the folder `audio_content_classifier` you will find the code and model used to identify the **exact Spotify title currently playing** from encrypted traffic. Full details and usage instructions can be found in the module’s `README.md`.
