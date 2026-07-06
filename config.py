from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent

# ---- File & Directory Paths ----

PCAP_PATH = BASE_DIR / "sample.pcap"


ARTIFACT_DIR = BASE_DIR / "temp_artifacts"


LOG_PATH = BASE_DIR / "logs" / "extractor.log"


ALERTS_PATH = BASE_DIR / "alerts.jsonl"


YARA_RULES_DIR = BASE_DIR / "yara_rules"
TSHARK_FULL_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Tshark Reassembly Preferences

TSHARK_PREFS = {
    "tcp.desegment_tcp_streams": "TRUE",
    "http.desegment_headers": "TRUE",
    "http.desegment_body": "TRUE"
}
