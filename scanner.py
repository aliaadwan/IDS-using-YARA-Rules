import os
import time
import json
import yara
import psutil
import logging
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class MetadataStore:
   # Reads/writes .meta.json next to each artifact.
    def __init__(self, logger: logging.Logger):
        self.log = logger

    @staticmethod
    def meta_path_for(file_path: Path) -> Path:
        return file_path.with_name(file_path.name + ".meta.json")

    def read(self, file_path: Path) -> dict:
        meta_path = self.meta_path_for(file_path)
        if not meta_path.exists():
            return {}
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    def update(self, file_path: Path, data: dict) -> None:
        meta_path = self.meta_path_for(file_path)
        metadata = self.read(file_path)
        metadata.update(data)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)


class YaraRuleManager:
    #Loads and holds compiled YARA rules.
    def __init__(self, rules_dir: Path, logger: logging.Logger):
        self.rules_dir = rules_dir
        self.log = logger
        self._rules = None

    def load(self):
        try:
            rules_map = {}
            for rule_file in self.rules_dir.glob("*.yar*"):
                rules_map[rule_file.stem] = str(rule_file)

            if not rules_map:
                self.log.warning(f"No YARA files (*.yar*) in {self.rules_dir}, loading rules.yara fallback")
                fallback = self.rules_dir / "rules.yara"
                if fallback.exists():
                    self._rules = yara.compile(filepath=str(fallback))
                    return self._rules
                self._rules = None
                return None

            self._rules = yara.compile(filepaths=rules_map)
            self.log.info(f"Successfully loaded YARA rules from {len(rules_map)} files.")
            return self._rules

        except Exception as e:
            self.log.error(f"Error loading YARA rules: {e}")
            self._rules = None
            return None

    @property
    def rules(self):
        return self._rules


class YaraScanner:
    #Scans extracted artifacts with compiled rules and writes match details into metadata.
    def __init__(self, artifact_dir: Path, metadata: MetadataStore, logger: logging.Logger):
        self.artifact_dir = artifact_dir
        self.metadata = metadata
        self.log = logger

    @staticmethod
    def _build_match_details(match_list, data: bytes) -> list[dict]:
        details = []

        for m in match_list:
            hit_strings = []

            for s in m.strings:

                if hasattr(s, "instances"):
                    for inst in s.instances:
                        off = inst.offset
                        sdata = inst.matched_data
                        ident = s.identifier

                        start_off = max(0, off - 16)
                        end_off = min(len(data), off + len(sdata) + 16)
                        snippet_hex = data[start_off:end_off].hex()

                        hit_strings.append({
                            "offset": off,
                            "identifier": ident,
                            "snippet_hex": snippet_hex
                        })


                elif isinstance(s, tuple):
                    off, ident, sdata = s
                    if isinstance(ident, bytes):
                        ident = ident.decode(errors="ignore")

                    start_off = max(0, off - 16)
                    end_off = min(len(data), off + len(sdata) + 16)
                    snippet_hex = data[start_off:end_off].hex()

                    hit_strings.append({
                        "offset": off,
                        "identifier": ident,
                        "snippet_hex": snippet_hex
                    })

            details.append({
                "rule": m.rule,
                "tags": m.tags,
                "meta": m.meta,
                "strings": hit_strings
            })

        return details

    def scan(self, rules) -> int:
        if rules is None:
            self.log.error("No YARA rules loaded — aborting")
            return 0

        process = psutil.Process(os.getpid())
        process.cpu_percent(interval=None)
        start = time.perf_counter()

        files_to_scan = [
            f for f in self.artifact_dir.rglob("*")
            if f.is_file() and not f.name.endswith(".meta.json")
        ]

        self.log.info(f"Scanning {len(files_to_scan)} extracted artifacts...")

        total_matches = 0

        for file in files_to_scan:
            try:
                meta = self.metadata.read(file)
                if meta.get("yara_matches"):
                    self.log.info(f"[SKIP] Already scanned: {file.name}")
                    continue

                data = file.read_bytes()
                match_list = rules.match(data=data)

                if match_list:
                    total_matches += len(match_list)
                    self.log.info(f"[MATCH] Found {len(match_list)} matches in {file.name}")

                    match_details = self._build_match_details(match_list, data)
                    self.metadata.update(file, {"yara_matches": match_details})

            except Exception as e:
                self.log.warning(f"[!] Error scanning {file.name}: {e}")

        elapsed = time.perf_counter() - start
        cpu = process.cpu_percent(interval=None) / psutil.cpu_count(logical=True)
        self.log.info(f"Scan Done: {len(files_to_scan)} files in {elapsed:.2f}s | CPU ~ {cpu}%")

        return total_matches


class AlertGenerator:

    def __init__(self, alerts_file: Path, metadata: MetadataStore, logger: logging.Logger):
        self.alerts_file = alerts_file
        self.metadata = metadata
        self.log = logger

    @staticmethod
    def _calc_severity(yara_matches: list[dict]) -> str:
        current = "INFO"
        for match in yara_matches:
            sev = (match.get("meta", {}) or {}).get("severity", "INFO")
            sev = str(sev).upper()
            tags = [str(t).lower() for t in (match.get("tags", []) or [])]

            if "malware" in tags or sev == "HIGH":
                return "HIGH"
            if sev == "MEDIUM":
                current = "MEDIUM"
        return current

    def generate(self, artifacts_dir: Path, default_pcap_path: str) -> int:
        if self.alerts_file.exists():
            self.alerts_file.unlink()

        self.log.info("Generating Alerts...")
        total_alerts = 0

        for flow in artifacts_dir.glob("flow_*"):
            if not flow.is_dir():
                continue

            flow_id = flow.name.replace("flow_", "")
            flow_alerts = []
            max_severity = "INFO"
            pcap_path = default_pcap_path

            for meta_path in flow.glob("*.meta.json"):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f) or {}

                    if "pcap" in meta:
                        pcap_path = meta["pcap"]

                    if meta.get("yara_matches"):
                        sev = self._calc_severity(meta["yara_matches"])
                        if sev == "HIGH":
                            max_severity = "HIGH"
                        elif sev == "MEDIUM" and max_severity == "INFO":
                            max_severity = "MEDIUM"

                        flow_alerts.append({
                            "artifact_sha256": meta.get("sha256"),
                            "protocol": meta.get("protocol"),
                            "file_size": meta.get("size"),
                            "matches": meta.get("yara_matches"),
                            "max_severity": sev
                        })

                except Exception as e:
                    self.log.error(f"Error in metadata {meta_path.name}: {e}")

            if flow_alerts:
                alert = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "flow_id": flow_id,
                    "summary": f"Malicious content detected in flow {flow_id}",
                    "max_severity": max_severity,
                    "pcap_path": pcap_path,
                    "artifacts_detected": flow_alerts
                }

                with open(self.alerts_file, "a", encoding="utf-8") as f:
                    json.dump(alert, f)
                    f.write("\n")

                total_alerts += 1
                self.log.info(f"[ALERT] Generated alert for flow {flow_id} (severity: {max_severity})")

        self.log.info("Alerts stored in: " + str(self.alerts_file))
        return total_alerts


class RulesWatcherHandler(FileSystemEventHandler):

    def __init__(self, rule_manager: YaraRuleManager):
        self.rule_manager = rule_manager

    def on_modified(self, event):
        if event.src_path.endswith(".yara") or event.src_path.endswith(".yar"):
            self.rule_manager.log.info("YARA rules updated — reloading...")
            self.rule_manager.load()


class RuleWatcher:

    def __init__(self, rules_dir: Path, rule_manager: YaraRuleManager, logger: logging.Logger):
        self.rules_dir = rules_dir
        self.rule_manager = rule_manager
        self.log = logger
        self._observer = None

    def start(self) -> Observer:
        handler = RulesWatcherHandler(self.rule_manager)
        observer = Observer()
        observer.schedule(handler, str(self.rules_dir), recursive=False)
        observer.start()
        self._observer = observer
        self.log.info("Watching YARA rules directory for updates...")
        return observer

    def stop(self):
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None
