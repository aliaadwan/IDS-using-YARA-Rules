from flask import Flask, render_template, abort
from pathlib import Path
import json
import config

app = Flask(__name__)
ALERTS_PATH = Path(config.ALERTS_PATH)

def load_alerts():
    alerts = []
    if ALERTS_PATH.exists():
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except:
                    pass
    return alerts

def build_dashboard_summary(alerts):
    summary = {"total": len(alerts), "high": 0, "medium": 0, "info": 0}
    for a in alerts:
        sev = (a.get("max_severity") or "INFO").upper()
        if sev == "HIGH": summary["high"] += 1
        elif sev == "MEDIUM": summary["medium"] += 1
        else: summary["info"] += 1
    return summary

def hex_to_ascii(hex_str: str) -> str:
    try:

        b = bytes.fromhex(hex_str)
        return "".join(chr(x) if 32 <= x < 127 else "." for x in b)
    except: return ""

app.jinja_env.filters["hex_to_ascii"] = hex_to_ascii

@app.route("/")
def index():
    alerts = load_alerts()
    summary = build_dashboard_summary(alerts)
    return render_template("index.html", alerts=alerts, summary=summary)

@app.route("/flow/<flow_id>")
def flow_details(flow_id):
    alerts = load_alerts()
    for alert in alerts:
        if alert["flow_id"] == flow_id:
            return render_template("details.html", alert=alert)
    abort(404)

