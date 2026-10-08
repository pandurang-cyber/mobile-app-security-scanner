# Mobile App Security Scanner

A lightweight static analysis web application for Android APK files built with Flask and Androguard.

## Features
- **Permission Abuse Detection**: Identifies dangerous Android permissions.
- **Obfuscation Analysis**: Heuristic check for class name obfuscation (ProGuard/R8).
- **Dockerized Deployment**: Ready to deploy on Render via Docker.

## How to Run Locally
1. Install dependencies: `pip install -r requirements.txt`
2. Run app: `python app.py`
3. Access at `http://localhost:5000`
