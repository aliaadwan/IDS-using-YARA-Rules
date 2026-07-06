# Intrusion Detection System (IDS) using YARA Rules

An integrated Network Intrusion Detection System (IDS) designed to extract files from packet captures (`.pcap`), scan them against specified **YARA rules**, and display the security alerts via a clean web interface.

## 🚀 Features
* **PCAP File Extraction:** Automatically extracts files from network traffic captures using `file_extractor.py`.
* **Signature-Based Scanning:** Uses YARA rules inside `yara_rules/` via `scanner.py` to identify hidden malware or anomalies.
* **Web Dashboard:** Built with Flask (`app.py`), featuring a frontend interface to view scan results and alert details.
* **Structured Alert Logging:** Stores real-time detections inside `alerts.jsonl` for fast indexing and auditing.

## 📁 Project Structure
Based on the repository architecture shown in `image_ebb069.png`:

* **`logs/`**
  * `extractor.log` - Contains logs from the file extraction process.
* **`templates/`**
  * `index.html` - The main dashboard web page.
  * `details.html` - Detailed view page for specific alerts.
* **`yara_rules/`** - Directory containing your `.yar` / `.yara` signature files.
* **`alerts.jsonl`** - JSON Lines log file containing generated alert data.
* **`app.py`** - Flask web application backend.
* **`config.py`** - Configuration settings and global variables.
* **`file_extractor.py`** - Script responsible for processing packet captures and extracting data.
* **`main.py`** - Main execution entry point for the IDS pipeline.
* **`sample.pcap`** - Sample network capture file used for testing the system.
* **`scanner.py`** - Core YARA scanning engine.

## 🛠️ Prerequisites
Make sure you have the following dependencies installed:
```bash
pip install flask yara-python scapy
