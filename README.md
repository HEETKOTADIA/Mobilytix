# Mobilytix

Mobilytix is an Android forensics project focused on simplifying evidence collection and analysis from mobile devices. The goal of the project is to bring common forensic tasks into a single workflow instead of relying on multiple separate tools.

## Overview

The platform helps investigators collect Android artifacts, analyze user activity, and generate structured forensic reports. It automates several repetitive investigation tasks and improves the overall investigation process.

## Features

- Android evidence acquisition using ADB
- Extraction of SMS, call logs, installed apps, metadata, and device details
- Timeline reconstruction of user activity
- Artifact analysis and anomaly detection
- Automated forensic reporting
- Centralized investigation workflow

## Tech Stack

- Python
- ADB
- SQLite
- JSON
- Linux / Windows

## Project Structure

```bash
Mobilytix/
├── acquisition/
├── analysis/
├── reporting/
├── utils/
├── main.py
└── README.md
Installation
git clone https://github.com/yourusername/mobilytix.git
cd mobilytix
pip install -r requirements.txt
Usage
python main.py

Connect the Android device with USB debugging enabled before starting the tool.


---

