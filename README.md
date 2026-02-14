# Malware Detector

An advanced desktop application for detecting and analyzing malware using machine learning, behavioral analysis, and signature-based detection techniques.


---

## Overview

Malware Detector is a Windows desktop application designed to analyze executable files and running processes using multiple detection approaches, including signature-based scanning, machine learning classification, and behavioral monitoring. The application integrates a modern frontend with a Python-based backend and is packaged as a standalone Electron desktop application.

---

## Features

- Real-time process scanning and monitoring
- Machine learning–based malware detection
- Signature-based detection with 636+ known SHA256, md5 and SH1 malware hashes
- Portable Executable (PE) file analysis
- Modern user interface built with Next.js and React
- Optional cloud integration using Supabase
- Standalone desktop application with embedded Python runtime

---

## Requirements

### For End Users (Pre-built Application)

- Windows 10/11 (64-bit)
- Minimum 2GB free disk space
- No additional software required

### For Developers

- Node.js 18+
- Python 3.11+
- Git
- fastapi 0.115.6
- uvicorn 0.34.0
- psutil 6.1.1
- watchdog 6.0.0
- pefile 2024.8.26
- scikit-learn 1.6.1
- pandas 2.2.3
- numpy 2.2.3
- python-multipart 0.0.6
- joblib 1.3.2
- dotenv 0.9.9
- python-dotenv 1.2.1 
- supabase 2.28.0

---

## Installation

### Option 1: Install Pre-built Application (Recommended)

1. Download the installer from the Releases page.
2. Run the installer.
3. Follow the installation instructions.
4. Launch the application from the Desktop shortcut or Start Menu.

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/ffotm/malwaredetector.git
cd malwaredetector

# Install dependencies
npm install

# Setup embedded Python
node setup-python.js

# Build the application
npm run package
```

The generated installer will be located in the `dist/` directory.

---

## Project Structure

```
malware-detector/
├── app/                    # Next.js frontend
├── backend/                # Python FastAPI backend
│   ├── api.py
│   ├── scanner.py
│   ├── ml_model.py
│   ├── db.py
│   └── requirements.txt
├── electron/               # Electron main process
│   ├── main.js
│   └── preload.js
├── public/
├── python-embedded/
└── package.json
```

---

## Development

### Start Frontend

```bash
npm run dev
```

### Start Backend

```bash
cd backend
python api.py
```

### Start Electron

```bash
npm run electron:dev
```

---

## Production Build

```bash
rm -rf dist/
npm run package
```

---

## Configuration

Create a `backend/.env` file for optional cloud features:

```env
SUPABASE_URL=your-supabase-url
SUPABASE_KEY=your-supabase-key
```

Alternatively, configure directly in `electron/main.js`.

---

## Detection Architecture

### 1. Signature-Based Detection

- Computes SHA256, md5, SH1 hash of the file
- Compares against internal malware signature database

### 2. Machine Learning Analysis

- Extracts PE file features
- Evaluates characteristics such as entropy, imports, and file structure
- Uses trained classification model to predict malicious probability

### 3. Behavioral Analysis

- Monitors runtime process behavior
- Detects suspicious activity patterns

### Scanning Workflow

User selects file → Hash calculation → Signature comparison  
↓  
PE feature extraction → ML prediction  
↓  
Behavioral evaluation → Threat scoring  
↓  
Results displayed to user  

---

## Docker Support

Pull the public image:

```bash
docker pull otmanifadia/malware-detector-api:1.0.0

Run:
docker run -p 8000:8000 otmanifadia/malware-detector-api:1.0.0

```

With environment variables:

```bash
docker run -p 8000:8000 \
  -e SUPABASE_URL=your-url \
  -e SUPABASE_KEY=your-key \
  malware-detector-api
```

API available at: http://localhost:8000

---

## API Endpoints

- GET /health
- GET /scan
- GET /scan/stream
- POST /scan/store

---

## Troubleshooting

### Application Does Not Start

Check logs:

C:\Users\j\AppData\Roaming\malware-detector\

Log files:
- app.log
- python_stdout.log
- python_stderr.log

### Backend Issues

Ensure:
- Dependencies are installed
- Port 8000 is available
- Embedded Python exists in `python-embedded/`

---

## Disclaimer

This software is intended strictly for educational and research purposes. The authors are not responsible for misuse or damage resulting from the use of this software. Users must ensure they have authorization before scanning files or systems.

---

## License

MIT License

Copyright (c) 2026 Otmani Fadia

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
