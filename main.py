import os
import sys
import logging
from pathlib import Path

import config
from app import app

from file_extractor import make_settings, ArtifactStore, PcapExtractor
from scanner import (
    MetadataStore,
    YaraRuleManager,
    YaraScanner,
    AlertGenerator,
    RuleWatcher,
)
def setup_logging() -> logging.Logger:
    #Configure logging once (ONLY here) to avoid duplicated handlers/colors.
    Path(config.LOG_PATH).parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.handlers.clear()  #  يمنع تكرار الـ handlers
    root.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    fh = logging.FileHandler(config.LOG_PATH, encoding="utf-8")
    fh.setFormatter(fmt)

    root.addHandler(sh)
    root.addHandler(fh)

    return logging.getLogger("main")


def main():
    log = setup_logging()
    logger = logging.getLogger()
    log.info("===== Starting YARA IDS Pipeline =====")

    settings = make_settings()

    Path(config.ARTIFACT_DIR).mkdir(parents=True, exist_ok=True)

    if not os.path.exists(config.PCAP_PATH):
        log.error(f"PCAP not found: {config.PCAP_PATH}")
        return

    # Step 1: Extraction
    log.info("Step 1: Extracting artifacts from PCAP...")
    store = ArtifactStore(settings.artifact_dir, logger)
    extractor = PcapExtractor(settings.tshark_path, store, logger)
    extractor.extract(str(config.PCAP_PATH))

    artifacts_dir = Path(config.ARTIFACT_DIR)
    rules_dir = Path(config.YARA_RULES_DIR)
    alerts_file = Path(config.ALERTS_PATH)

    metadata = MetadataStore(logger)
    rule_manager = YaraRuleManager(rules_dir, logger)
    scanner_obj = YaraScanner(artifacts_dir, metadata, logger)
    alerts = AlertGenerator(alerts_file, metadata, logger)

    # Step 2: Load rules
    log.info("Step 2: Loading YARA rules...")
    rules = rule_manager.load()
    if rules is None:
        log.error("Could not load YARA rules. Stopping.")
        return

    # Step 3: Watcher
    log.info("Step 3: Starting YARA Hot-Reload watcher...")
    watcher = RuleWatcher(rules_dir, rule_manager, logger)
    watcher.start()

    try:
        # Step 4: Scan
        log.info("Step 4: Running YARA scanner...")
        total_matches = scanner_obj.scan(rule_manager.rules)
        log.info(f"Scanning complete. Found {total_matches} YARA matches.")

        # Step 5: Alerts
        log.info("Step 5: Generating Alerts from metadata...")
        total_alerts = alerts.generate(artifacts_dir, default_pcap_path=str(config.PCAP_PATH))
        log.info(f"Pipeline completed successfully! Total alerts: {total_alerts}")

        # Step 6: UI
        log.info("Step 6: Launching Web Dashboard...")
        app.run(debug=True, use_reloader=False)

    finally:
        watcher.stop()


if __name__ == "__main__":
    main()
