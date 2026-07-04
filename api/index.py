import json
import time
import uuid
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from http.server import BaseHTTPRequestHandler


class AlertStore:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.alerts = []
            cls._instance.telemetry = defaultdict(list)
            cls._instance.whitelist = set()
            cls._instance.stats = {
                "total_alerts": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }
            cls._instance.sample_counts = {}
            cls._instance.hardware_state = {
                "camera": {"active": False, "apps": []},
                "microphone": {"active": False, "apps": []},
            }
        return cls._instance

    def add_alert(self, alert):
        alert["id"] = len(self.alerts) + 1
        alert["created_at"] = datetime.utcnow().isoformat()
        alert["dismissed"] = 0
        alert["whitelisted"] = 0
        self.alerts.insert(0, alert)
        self.stats["total_alerts"] += 1
        severity = alert.get("severity", "LOW")
        if severity == "CRITICAL":
            self.stats["critical_count"] += 1
        elif severity == "HIGH":
            self.stats["high_count"] += 1
        elif severity == "MEDIUM":
            self.stats["medium_count"] += 1
        else:
            self.stats["low_count"] += 1
        return alert["id"]

    def get_alerts(self, limit=50, offset=0, severity=None):
        filtered = self.alerts
        if severity:
            filtered = [a for a in filtered if a.get("severity") == severity]
        return filtered[offset:offset + limit]


FEATURE_NAMES = {
    "process": [
        "is_first_time", "is_background", "is_signed",
        "thread_count", "memory_usage", "cpu_percent", "handle_count",
    ],
    "network": [
        "is_foreign_ip", "is_suspicious_port", "bytes_delta",
        "connection_count", "port_number",
    ],
    "hardware": [
        "is_first_time", "is_background", "is_signed", "app_is_known",
    ],
    "filesystem": [
        "write_burst", "extension_entropy", "rename_count",
        "delete_count", "file_count",
    ],
    "idle": [
        "cpu_spike", "ram_spike", "disk_spike",
        "network_spike", "process_count",
    ],
}


class AnomalyEngine:
    def __init__(self):
        self.models = {}
        self.explainers = {}
        self.sample_counts = {}
        self.baseline_buffer = defaultdict(list)

    def update(self, pillar, features):
        if pillar not in self.sample_counts:
            self.sample_counts[pillar] = 0
        self.sample_counts[pillar] += 1
        count = self.sample_counts[pillar]

        feature_names = FEATURE_NAMES.get(pillar, [])
        x = np.array([[features.get(f, 0.0) for f in feature_names]])

        if pillar not in self.models:
            if count < 200:
                self.baseline_buffer[pillar].append(features)
                return {
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "shap_values": {},
                    "baseline_mode": True,
                    "samples_remaining": 200 - count,
                }
            self._train_model(pillar)

        if pillar not in self.models:
            return None

        return self._score(pillar, x)

    def _train_model(self, pillar):
        from sklearn.ensemble import IsolationForest

        snapshots = self.baseline_buffer.get(pillar, [])
        if len(snapshots) < 50:
            return

        feature_names = FEATURE_NAMES.get(pillar, [])
        x = np.array([[s.get(f, 0.0) for f in feature_names] for s in snapshots[-200:]])

        model = IsolationForest(
            contamination=0.1, random_state=42,
            n_estimators=100, max_samples="auto",
        )
        model.fit(x)
        self.models[pillar] = model

        try:
            import shap
            self.explainers[pillar] = shap.TreeExplainer(model)
        except Exception:
            self.explainers[pillar] = None

    def _score(self, pillar, x):
        model = self.models[pillar]
        raw_score = model.decision_function(x)[0]
        prediction = model.predict(x)[0]
        is_anomaly = prediction == -1
        score_normalized = max(0.0, min(100.0, (0.5 - raw_score) * 200))

        shap_dict = {}
        if pillar in self.explainers and self.explainers[pillar] is not None:
            try:
                sv = self.explainers[pillar].shap_values(x)
                feature_names = FEATURE_NAMES.get(pillar, [])
                if isinstance(sv, np.ndarray):
                    vals = sv[0] if sv.ndim == 2 else sv.flatten()
                elif isinstance(sv, list):
                    vals = np.array(sv[0]) if sv else np.zeros(len(feature_names))
                else:
                    vals = np.zeros(len(feature_names))
                for i, name in enumerate(feature_names):
                    if i < len(vals):
                        shap_dict[name] = round(float(vals[i]), 4)
            except Exception:
                pass

        return {
            "anomaly_score": round(score_normalized, 2),
            "is_anomaly": is_anomaly,
            "shap_values": shap_dict,
            "baseline_mode": False,
        }


class RuleEngine:
    def __init__(self):
        self.rules = [
            {"name": "foreign_ip", "field": "is_foreign_ip", "op": "==", "value": True, "severity": "HIGH"},
            {"name": "suspicious_port", "field": "is_suspicious_port", "op": "==", "value": True, "severity": "HIGH"},
            {"name": "first_time_camera", "field": "is_first_time", "op": "==", "value": True, "watcher": "HardwareWatcher", "severity": "HIGH"},
            {"name": "first_time_mic", "field": "is_first_time", "op": "==", "value": True, "watcher": "HardwareWatcher", "severity": "HIGH"},
        ]

    def match(self, event):
        matches = []
        for rule in self.rules:
            watcher_match = "watcher" not in rule or event.get("watcher") == rule["watcher"]
            if watcher_match and event.get(rule["field"]) == rule["value"]:
                matches.append(rule)
        return matches


def classify(anomaly_result, rule_matches):
    if anomaly_result and anomaly_result.get("is_anomaly"):
        score = anomaly_result.get("anomaly_score", 0)
        if score > 75:
            return "CRITICAL"
        elif score > 50:
            return "HIGH"
        elif score > 25:
            return "MEDIUM"
        return "LOW"

    for m in rule_matches:
        if m.get("severity") == "CRITICAL":
            return "CRITICAL"
        elif m.get("severity") == "HIGH":
            return "HIGH"
        elif m.get("severity") == "MEDIUM":
            return "MEDIUM"

    return "SAFE"


SUMMARY_TEMPLATES = {
    "NETWORK_SUSPICIOUS": "{process_name} opened a connection to {remote_ip}:{remote_port}.",
    "CAMERA_ACCESS": "Your camera was accessed by {process_name}.",
    "MIC_ACCESS": "Your microphone is now active. Process responsible: {process_name}.",
    "PROCESS_SUSPICIOUS": "Anomalous process detected: {process_name}.",
}

RECOMMENDATIONS = {
    "NETWORK_SUSPICIOUS": "Block {process_name} in Windows Firewall.",
    "CAMERA_ACCESS": "If you did not open a video app, terminate {process_name} immediately.",
    "MIC_ACCESS": "Verify if a call or recording app is open.",
    "PROCESS_SUSPICIOUS": "Review this process in Task Manager.",
}


def explain_event(event, anomaly_result=None):
    event_type = event.get("type", "UNKNOWN")
    template = SUMMARY_TEMPLATES.get(event_type, "Unknown event detected.")
    try:
        base_text = template.format(**event)
    except KeyError:
        base_text = template

    shap_values = {}
    if anomaly_result and anomaly_result.get("shap_values"):
        shap_values = anomaly_result["shap_values"]

    top_reasons = []
    for feature, value in sorted(shap_values.items(), key=lambda x: abs(x[1]), reverse=True)[:3]:
        direction = "increases" if value > 0 else "decreases"
        top_reasons.append(f"{feature} contributes {abs(value)*100:.1f}% toward suspicion.")

    full_summary = base_text
    if top_reasons:
        full_summary += " " + " ".join(top_reasons)

    recommendation = RECOMMENDATIONS.get(event_type, "Review this event.")
    try:
        recommendation = recommendation.format(**event)
    except KeyError:
        pass

    return {
        "summary": full_summary,
        "reasons": top_reasons,
        "shap_values": shap_values,
        "recommendation": recommendation,
        "threat_level": event.get("severity", "MEDIUM"),
    }


store = AlertStore()
anomaly_engine = AnomalyEngine()
rule_engine = RuleEngine()


def process_event(pillar, event):
    features = event.get("features", {})
    anomaly_result = anomaly_engine.update(pillar, features)

    rule_matches = rule_engine.match(event)
    severity = classify(anomaly_result, rule_matches)

    if severity == "SAFE":
        return None

    event["severity"] = severity
    explanation = explain_event(event, anomaly_result)
    event.update(explanation)

    alert_id = store.add_alert(event)
    event["id"] = alert_id
    return event


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/api/status":
            self._json_response({
                "status": "online",
                "uptime": time.time(),
                "version": "1.0.0",
                "watchers": ["process", "network", "hardware", "filesystem", "idle"],
                "anomaly_engine": "active",
                "model_status": {
                    p: {"trained": p in anomaly_engine.models, "samples": anomaly_engine.sample_counts.get(p, 0)}
                    for p in FEATURE_NAMES
                },
            })

        elif path == "/api/alerts":
            alerts = store.get_alerts(limit=50)
            self._json_response(alerts)

        elif path == "/api/hardware":
            self._json_response(store.hardware_state)

        elif path == "/api/stats":
            self._json_response(store.stats)

        elif path == "/api/whitelist":
            self._json_response(list(store.whitelist))

        elif path == "/api/processes":
            self._json_response({"processes": []})

        elif path == "/api/network":
            self._json_response({"connections": []})

        elif path == "/api/settings":
            self._json_response({
                "sensitivity": 0.5,
                "voice_enabled": True,
                "watcher_toggles": {p: True for p in FEATURE_NAMES},
            })

        elif path == "/api/export/csv":
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.end_headers()
            lines = ["id,type,process_name,severity,summary,created_at"]
            for a in store.alerts[:100]:
                lines.append(f'{a["id"]},{a.get("type","")},{a.get("process_name","")},{a.get("severity","")},"{a.get("summary","")}",{a.get("created_at","")}')
            self.wfile.write("\n".join(lines).encode())

        else:
            self._json_response({"error": "Not found"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
        path = self.path.split("?")[0]

        if path == "/api/events":
            pillar = body.get("pillar", "process")
            event = body.get("event", {})
            result = process_event(pillar, event)
            self._json_response({"processed": result is not None, "alert": result})

        elif path == "/api/simulate":
            pillar = body.get("pillar", "network")
            event = body.get("event", {
                "type": "NETWORK_SUSPICIOUS",
                "process_name": "unknown.exe",
                "pid": 0,
                "remote_ip": "192.168.1.100",
                "remote_port": 4444,
                "is_foreign_ip": True,
                "is_suspicious_port": True,
                "features": {
                    "is_foreign_ip": 1.0,
                    "is_suspicious_port": 1.0,
                    "bytes_delta": 50000.0,
                    "connection_count": 0.05,
                    "port_number": 0.068,
                },
            })
            result = process_event(pillar, event)
            self._json_response({"processed": result is not None, "alert": result})

        elif path == "/api/settings":
            self._json_response({"ok": True})

        elif path == "/api/actions/whitelist":
            name = body.get("process_name", "")
            if name:
                store.whitelist.add(name.lower())
            self._json_response({"ok": True})

        elif path == "/api/actions/dismiss":
            alert_id = body.get("alert_id")
            for a in store.alerts:
                if a.get("id") == alert_id:
                    a["dismissed"] = 1
            self._json_response({"ok": True})

        elif path == "/api/actions/kill":
            self._json_response({"ok": True, "message": "Process kill not available on Vercel"})

        else:
            self._json_response({"error": "Not found"}, 404)

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/actions/whitelist/"):
            name = path.split("/")[-1]
            store.whitelist.discard(name.lower())
            self._json_response({"ok": True})
        else:
            self._json_response({"error": "Not found"}, 404)

    def _json_response(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
