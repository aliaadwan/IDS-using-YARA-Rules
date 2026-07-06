import json
import hashlib
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
import config


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Settings:
    artifact_dir: Path
    tshark_path: str


def make_settings() -> Settings:
    artifact_dir = Path(config.ARTIFACT_DIR)
    tshark_path = getattr(config, "TSHARK_FULL_PATH", "tshark")
    return Settings(artifact_dir=artifact_dir, tshark_path=tshark_path)


class ArtifactStore:
    def __init__(self, base_dir: Path, logger: logging.Logger | None = None):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.log = logger or logging.getLogger(__name__)

    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def save(self, data: bytes, info: dict) -> str:
        sha = self.sha256_bytes(data)
        stream_id = info.get("stream_id", "unknown")

        flow_dir = self.base_dir / f"flow_{stream_id}"
        flow_dir.mkdir(parents=True, exist_ok=True)

        file_path = flow_dir / sha
        metadata_path = flow_dir / f"{sha}.meta.json"

        with open(file_path, "wb") as f:
            f.write(data)

        info = dict(info)  # avoid mutating caller dict
        info.update({
            "sha256": sha,
            "size": len(data),
            "flow_dir": str(flow_dir)
        })

        with open(metadata_path, "w", encoding="utf-8") as meta:
            json.dump(info, meta, indent=2)

        self.log.info(f"Saved artifact {sha} ({len(data)} bytes) in flow_{stream_id}")
        return sha


class PcapExtractor:
    def __init__(self, tshark_path: str, store: ArtifactStore, logger: logging.Logger | None = None):
        self.tshark = tshark_path
        self.store = store
        self.log = logger or logging.getLogger(__name__)

    def _list_tcp_streams(self, pcap_path: str) -> list[str]:
        cmd = [
            self.tshark,
            "-r", str(pcap_path),
            "-T", "fields",
            "-e", "tcp.stream",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        stream_ids = sorted(list(set(filter(None, proc.stdout.splitlines()))), key=int)
        return stream_ids

    @staticmethod
    def _extract_hex_from_follow_output(output: str) -> str:
        hex_data = ""
        for line in output.splitlines():
            clean_line = line.strip()

            if clean_line.startswith(("Follow:", "Filter:", "Node")) or clean_line.startswith("="):
                continue

            try:
                int(clean_line, 16)
                hex_data += clean_line
            except ValueError:
                continue

        return hex_data

    def extract(self, pcap_path: str) -> int:
        self.log.info(f"Opening PCAP for TShark Extraction: {pcap_path}")
        self.log.info("Identifying TCP streams...")

        try:
            stream_ids = self._list_tcp_streams(pcap_path)
        except Exception as e:
            self.log.error(f"Failed to list streams: {e}")
            return 0

        streams_extracted = 0

        for sid in stream_ids:
            try:
                cmd = [
                    self.tshark,
                    "-r", str(pcap_path),
                    "-z", f"follow,tcp,raw,{sid}",
                    "-q"
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, check=True)

                hex_data = self._extract_hex_from_follow_output(proc.stdout)
                if not hex_data:
                    continue

                stream_bytes = bytes.fromhex(hex_data)

                self.store.save(stream_bytes, {
                    "protocol": "TCP",
                    "stream_id": sid,
                    "pcap": pcap_path,
                    "note": "Full Reassembled TCP Stream"
                })

                if b"HTTP/" in stream_bytes:
                    parts = stream_bytes.split(b"\r\n\r\n", 1)
                    if len(parts) == 2 and len(parts[1]) > 0:
                        self.store.save(parts[1], {
                            "protocol": "HTTP",
                            "stream_id": sid,
                            "pcap": pcap_path,
                            "note": "Extracted HTTP Body"
                        })

                streams_extracted += 1

            except Exception as e:
                self.log.error(f"Error extracting stream {sid}: {e}")
                continue

        self.log.info(f"Extraction complete. Extracted {streams_extracted} streams.")
        return streams_extracted
