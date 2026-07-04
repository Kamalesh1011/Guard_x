import json
import time
import numpy as np
from datetime import datetime
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
                "total_alerts": 0, "critical_count": 0,
                "high_count": 0, "medium_count": 0, "low_count": 0,
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
        sev = alert.get("severity", "LOW")
        if sev == "CRITICAL": self.stats["critical_count"] += 1
        elif sev == "HIGH": self.stats["high_count"] += 1
        elif sev == "MEDIUM": self.stats["medium_count"] += 1
        else: self.stats["low_count"] += 1
        return alert["id"]

    def get_alerts(self, limit=50, offset=0, severity=None):
        filtered = self.alerts
        if severity:
            filtered = [a for a in filtered if a.get("severity") == severity]
        return filtered[offset:offset + limit]


FEATURE_NAMES = {
    "process": ["is_first_time", "is_background", "is_signed", "thread_count", "memory_usage", "cpu_percent", "handle_count"],
    "network": ["is_foreign_ip", "is_suspicious_port", "bytes_delta", "connection_count", "port_number"],
    "hardware": ["is_first_time", "is_background", "is_signed", "app_is_known"],
    "filesystem": ["write_burst", "extension_entropy", "rename_count", "delete_count", "file_count"],
    "idle": ["cpu_spike", "ram_spike", "disk_spike", "network_spike", "process_count"],
}


SUSPICIOUS_PORTS = {
    4444: {"name": "Metasploit/Cobalt Strike", "risk": "CRITICAL", "ttp": "T1059.001", "description": "Port 4444 is the default listener for Metasploit framework and Cobalt Strike beacons. This is almost always malicious unless you are running a penetration test."},
    1337: {"name": "Waste/Backdoor", "risk": "HIGH", "ttp": "T1571", "description": "Port 1337 (leet) is commonly used by backdoors, trojans, and C2 frameworks to avoid detection."},
    31337: {"name": "Back Orifice/BO2K", "risk": "CRITICAL", "ttp": "T1219", "description": "Port 31337 is the classic Back Orifice trojan port. Any connection to this port indicates active malware compromise."},
    6666: {"name": "IRC Botnet/C2", "risk": "CRITICAL", "ttp": "T1071.001", "description": "Port 6666 is historically associated with IRC-based botnets and malware command channels."},
    8080: {"name": "HTTP Proxy/Tunnel", "risk": "MEDIUM", "ttp": "T1090", "description": "Port 8080 is an alternate HTTP port often used by proxies, C2 tunnels, or data exfiltration channels."},
    23: {"name": "Telnet", "risk": "HIGH", "ttp": "T1021.004", "description": "Telnet transmits credentials in plaintext. This may indicate lateral movement or credential theft."},
    1080: {"name": "SOCKS Proxy", "risk": "HIGH", "ttp": "T1090", "description": "SOCKS proxy detected. Attackers use this to tunnel traffic through compromised hosts."},
    5555: {"name": "Android Debug/Fastboot", "risk": "MEDIUM", "ttp": "T1200", "description": "Port 5555 is used by Android Debug Bridge. May indicate device debugging or malicious app installation."},
    7777: {"name": "Trojan/Games", "risk": "MEDIUM", "ttp": "T1571", "description": "Port 7777 is commonly used by trojans and game cheats that open backdoors."},
    9001: {"name": "Tor SOCKS", "risk": "HIGH", "ttp": "T1090.003", "description": "Tor network proxy detected. Used to anonymize malicious traffic and bypass security controls."},
}

FOREIGN_IP_CONTEXT = {
    "known_malicious": {"ranges": ["45.33.32.", "185.220.101.", "198.51.100."], "description": "This IP range is associated with known threat actors and has been flagged in multiple threat intelligence feeds."},
    "bulletproof_hosting": {"ranges": ["194.26.29.", "91.215.85.", "185.56.80."], "description": "This IP belongs to a bulletproof hosting provider known for sheltering criminal infrastructure."},
    "cloud_vps": {"ranges": ["35.", "52.", "34.", "54.", "18.161.", "18.216.", "13.", "3.173.", "103.28."], "description": "This IP is from a cloud VPS provider. Legitimate services use these, but so do attackers for C2 servers and payload delivery."},
}

CAMERA_MIC_CONTEXT = {
    "surveillance": "Unauthorized camera/microphone access is a primary indicator of surveillance malware, stalkerware, or remote access trojans (RATs).",
    "rat_indicator": "RATs like njRAT, DarkComet, and Quasar routinely abuse camera/microphone for remote surveillance of victims.",
}


def explain_network_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    ip = event.get("remote_ip", "unknown")
    port = event.get("remote_port", 0)
    is_foreign = event.get("is_foreign_ip", False)
    is_susp_port = event.get("is_suspicious_port", False)
    risk_factors = []
    total_risk = 0.0

    port_info = SUSPICIOUS_PORTS.get(port, None)
    if port_info:
        risk_factors.append({"factor": f"Suspicious Port {port}", "contribution": shap_values.get("is_suspicious_port", 0), "detail": port_info["description"], "ttp": port_info["ttp"], "risk_level": port_info["risk"]})
        total_risk += abs(shap_values.get("is_suspicious_port", 0))

    if is_foreign:
        ip_desc = "Foreign IP detected."
        ip_class = "cloud_vps"
        for cls, info in FOREIGN_IP_CONTEXT.items():
            for prefix in info["ranges"]:
                if ip.startswith(prefix):
                    ip_class = cls
                    ip_desc = info["description"]
                    break
        risk_factors.append({"factor": "Foreign IP Connection", "contribution": shap_values.get("is_foreign_ip", 0), "detail": ip_desc, "ttp": "T1071", "risk_level": "HIGH" if ip_class in ("known_malicious", "bulletproof_hosting") else "MEDIUM"})
        total_risk += abs(shap_values.get("is_foreign_ip", 0))

    bytes_delta = shap_values.get("bytes_delta", 0)
    if bytes_delta > 0.3:
        risk_factors.append({"factor": "High Data Transfer", "contribution": bytes_delta, "detail": "Abnormally high bytes transferred. This may indicate data exfiltration, payload download, or C2 keepalive traffic.", "ttp": "T1041", "risk_level": "HIGH" if bytes_delta > 0.5 else "MEDIUM"})
        total_risk += abs(bytes_delta)

    if anomaly_score > 75:
        risk_factors.append({"factor": "Anomaly Score", "contribution": anomaly_score / 100, "detail": f"The machine learning model flagged this connection with {anomaly_score:.0f}/100 anomaly score based on historical behavior patterns.", "ttp": "Behavioral Analysis", "risk_level": "CRITICAL" if anomaly_score > 90 else "HIGH"})

    severity = "CRITICAL" if total_risk > 1.5 or anomaly_score > 85 else "HIGH" if total_risk > 0.8 else "MEDIUM"
    summary = f"{proc} established an outbound connection to {ip}:{port}."
    if port_info:
        summary += f" Port {port} is associated with {port_info['name']}."
    if is_foreign:
        summary += " The destination is outside your local network."

    recommendation = f"Investigate {proc} immediately. "
    if port_info and port_info["risk"] == "CRITICAL":
        recommendation += f"Port {port} ({port_info['name']}) is a known malicious indicator. "
    recommendation += f"Check the process origin, command line arguments, and network behavior. If unauthorized, block {ip} in your firewall and terminate {proc}."

    return {"summary": summary, "risk_factors": risk_factors, "total_risk_score": round(total_risk, 2), "severity": severity, "recommendation": recommendation, "mitre_ttps": list(set(rf["ttp"] for rf in risk_factors))}


def explain_camera_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    is_first = event.get("is_first_time", False)
    is_bg = event.get("is_background", False)
    is_known = event.get("app_is_known", False)
    risk_factors = []

    if is_first:
        risk_factors.append({"factor": "First-Time Camera Access", "contribution": shap_values.get("is_first_time", 0), "detail": f"{proc} has never accessed your camera before in the monitored period. New camera access by an unknown application is a critical privacy concern.", "ttp": "T1125", "risk_level": "HIGH"})
    if is_bg:
        risk_factors.append({"factor": "Background Access", "contribution": shap_values.get("is_background", 0), "detail": f"{proc} accessed your camera while running in the background with no visible window. Legitimate apps require user interaction to access the camera.", "ttp": "T1203", "risk_level": "CRITICAL"})
    if not is_known:
        risk_factors.append({"factor": "Untrusted Application", "contribution": shap_values.get("app_is_known", 0), "detail": f"{proc} is not in your trusted application list. This application has not been verified or approved for camera access.", "ttp": "T1200", "risk_level": "MEDIUM"})

    summary = f"Your integrated camera was activated by {proc}."
    if is_first: summary += " This is the first time this application has accessed your camera."
    if is_bg: summary += " The application is running in the background."

    recommendation = f"Verify if {proc} is an application you trust. "
    if is_bg: recommendation += "The background access pattern is suspicious. "
    recommendation += f"If you did not initiate camera use, terminate {proc} immediately via Task Manager. Check Camera privacy settings in Windows to revoke access for unknown apps."

    return {"summary": summary, "risk_factors": risk_factors, "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2), "severity": "CRITICAL" if is_bg else "HIGH", "recommendation": recommendation, "mitre_ttps": list(set(rf["ttp"] for rf in risk_factors)), "threat_context": CAMERA_MIC_CONTEXT["surveillance"]}


def explain_mic_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    is_first = event.get("is_first_time", False)
    is_bg = event.get("is_background", False)
    is_known = event.get("app_is_known", False)
    risk_factors = []

    if is_first:
        risk_factors.append({"factor": "First-Time Microphone Access", "contribution": shap_values.get("is_first_time", 0), "detail": f"{proc} has never used your microphone before. Unauthorized audio capture is a primary vector for espionage and data theft.", "ttp": "T1123", "risk_level": "HIGH"})
    if is_bg:
        risk_factors.append({"factor": "Silent Background Recording", "contribution": shap_values.get("is_background", 0), "detail": f"{proc} is capturing audio while hidden. This is the exact behavior pattern of spyware and RATs like njRAT and DarkComet.", "ttp": "T1123", "risk_level": "CRITICAL"})

    summary = f"Your microphone is being used by {proc}."
    if is_first: summary += " This application has never accessed your microphone before."
    if is_bg: summary += " The application is running in the background without a visible interface."

    recommendation = f"Investigate {proc}. "
    if is_bg: recommendation += "Background microphone access without user interaction is highly suspicious. "
    recommendation += f"Open Sound Settings to see which app is using the microphone. If {proc} is unknown, terminate it and run a full malware scan."

    return {"summary": summary, "risk_factors": risk_factors, "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2), "severity": "CRITICAL" if is_bg else "HIGH", "recommendation": recommendation, "mitre_ttps": list(set(rf["ttp"] for rf in risk_factors)), "threat_context": CAMERA_MIC_CONTEXT["rat_indicator"]}


def explain_process_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    risk_factors = []

    signals = {
        "is_unsigned": "The process lacks a valid digital signature. Unsigned executables are a primary indicator of malware.",
        "from_temp": "The process is executing from a temporary directory. This is a common malware evasion technique.",
        "parent_child_pair": "The process was spawned by an unexpected parent. This parent-child anomaly often indicates script-based malware execution.",
        "has_window": "The process has no visible user interface, suggesting it is designed to run silently in the background.",
        "encoded_cmdline": "The command line contains encoded content. Attackers encode commands to bypass security tools.",
    }

    for key, detail in signals.items():
        val = shap_values.get(key, 0)
        if val > 0.1:
            risk_factors.append({"factor": key.replace("_", " ").title(), "contribution": val, "detail": detail, "ttp": "T1059", "risk_level": "HIGH"})

    cpu = shap_values.get("cpu_percent", 0)
    mem = shap_values.get("memory_usage", 0)
    if cpu > 0.4:
        risk_factors.append({"factor": "CPU Anomaly", "contribution": cpu, "detail": "Abnormal CPU usage detected. This may indicate cryptomining, brute-force attacks, or payload execution.", "ttp": "T1496", "risk_level": "MEDIUM"})
    if mem > 0.4:
        risk_factors.append({"factor": "Memory Anomaly", "contribution": mem, "detail": "Abnormal memory consumption suggests possible code injection, credential dumping, or reflective DLL loading.", "ttp": "T1055", "risk_level": "HIGH"})

    summary = f"Suspicious process detected: {proc}."
    if risk_factors: summary += f" {len(risk_factors)} risk indicators identified."

    recommendation = f"Review {proc} in Task Manager. Check its file location, digital signature, and command line. If the process is unknown or behaving abnormally, terminate it and run a full antivirus scan."

    return {"summary": summary, "risk_factors": risk_factors, "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2), "severity": "CRITICAL" if len(risk_factors) >= 3 else "HIGH" if len(risk_factors) >= 2 else "MEDIUM", "recommendation": recommendation, "mitre_ttps": list(set(rf["ttp"] for rf in risk_factors))}


def explain_ransomware_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    risk_factors = []

    write_burst = shap_values.get("write_burst", 0)
    ext_change = shap_values.get("extension_entropy", 0)
    rename_count = shap_values.get("rename_count", 0)

    if write_burst > 0.3:
        risk_factors.append({"factor": "Rapid File Encryption", "contribution": write_burst, "detail": "Rapid file modification in short timeframes is the primary behavioral indicator of ransomware encryption.", "ttp": "T1486", "risk_level": "CRITICAL"})
    if ext_change > 0.3:
        risk_factors.append({"factor": "File Extension Tampering", "contribution": ext_change, "detail": "Files being renamed with unknown extensions (e.g., .locked, .encrypted, .crypto) confirms active encryption.", "ttp": "T1486", "risk_level": "CRITICAL"})
    if rename_count > 0.3:
        risk_factors.append({"factor": "Mass File Renaming", "contribution": rename_count, "detail": "Ransom notes being dropped in multiple directories indicates the encryption phase is complete.", "ttp": "T1486", "risk_level": "CRITICAL"})

    summary = f"Ransomware behavior detected from {proc}."
    if risk_factors: summary += f" {len(risk_factors)} encryption indicators active."

    recommendation = "DISCONNECT FROM THE NETWORK IMMEDIATELY. Do not restart the computer. Check for ransom notes in affected directories. Use ransomware decryption tools from nomoreransom.org if available. Report to your security team."

    return {"summary": summary, "risk_factors": risk_factors, "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2), "severity": "CRITICAL", "recommendation": recommendation, "mitre_ttps": ["T1486"], "threat_context": "Ransomware is the most destructive form of malware. Immediate isolation is critical."}


EXPLAINERS = {
    "NETWORK_SUSPICIOUS": explain_network_event,
    "CAMERA_ACCESS": explain_camera_event,
    "MIC_ACCESS": explain_mic_event,
    "PROCESS_SUSPICIOUS": explain_process_event,
    "RANSOMWARE_BURST": explain_ransomware_event,
}


def explain_event(event, anomaly_result=None):
    event_type = event.get("type", "UNKNOWN")
    shap_values = anomaly_result.get("shap_values", {}) if anomaly_result else {}
    anomaly_score = anomaly_result.get("anomaly_score", 0) if anomaly_result else 0
    explainer = EXPLAINERS.get(event_type)
    if explainer:
        result = explainer(event, shap_values, anomaly_score)
        result["shap_values"] = shap_values
        result["anomaly_score"] = anomaly_score
        result["threat_level"] = result.get("severity", "MEDIUM")
        return result
    return {"summary": f"Event detected: {event_type} from {event.get('process_name', 'unknown')}.", "risk_factors": [], "total_risk_score": 0, "severity": event.get("severity", "MEDIUM"), "recommendation": "Review this event and take action if needed.", "shap_values": shap_values, "anomaly_score": anomaly_score, "mitre_ttps": []}


class AnomalyEngine:
    def __init__(self):
        self.models = {}
        self.sample_counts = {}
        self.baseline_buffer = defaultdict(list)
        self.feature_importances = {}

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
                return {"anomaly_score": 0.0, "is_anomaly": False, "shap_values": {}, "baseline_mode": True, "samples_remaining": 200 - count}
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
        model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100, max_samples="auto")
        model.fit(x)
        self.models[pillar] = model
        importances = np.mean([tree.feature_importances_ for tree in model.estimators_], axis=0)
        self.feature_importances[pillar] = {name: round(float(importances[i]), 4) for i, name in enumerate(feature_names) if i < len(importances)}

    def _score(self, pillar, x):
        model = self.models[pillar]
        raw_score = model.decision_function(x)[0]
        prediction = model.predict(x)[0]
        is_anomaly = prediction == -1
        score_normalized = max(0.0, min(100.0, (0.5 - raw_score) * 200))
        shap_dict = {}
        importances = self.feature_importances.get(pillar, {})
        feature_names = FEATURE_NAMES.get(pillar, [])
        sample = x[0] if len(x) > 0 else np.zeros(len(feature_names))
        for i, name in enumerate(feature_names):
            if i < len(sample) and name in importances:
                contribution = abs(float(sample[i])) * importances[name]
                shap_dict[name] = round(contribution, 4)
        return {"anomaly_score": round(score_normalized, 2), "is_anomaly": is_anomaly, "shap_values": shap_dict, "baseline_mode": False}


class RuleEngine:
    def __init__(self):
        self.rules = [
            {"name": "foreign_ip", "field": "is_foreign_ip", "op": "==", "value": True, "severity": "HIGH"},
            {"name": "suspicious_port", "field": "is_suspicious_port", "op": "==", "value": True, "severity": "HIGH"},
            {"name": "first_time_camera", "field": "is_first_time", "op": "==", "value": True, "watcher": "HardwareWatcher", "severity": "HIGH"},
            {"name": "first_time_mic", "field": "is_first_time", "op": "==", "value": True, "watcher": "HardwareWatcher", "severity": "HIGH"},
            {"name": "write_burst", "field": "write_burst", "op": ">", "value": 0.5, "severity": "CRITICAL"},
            {"name": "extension_entropy", "field": "extension_entropy", "op": ">", "value": 0.5, "severity": "CRITICAL"},
            {"name": "is_unsigned", "field": "is_unsigned", "op": "==", "value": True, "severity": "HIGH"},
            {"name": "from_temp", "field": "from_temp", "op": "==", "value": True, "severity": "HIGH"},
            {"name": "parent_child_pair", "field": "parent_child_pair", "op": "==", "value": True, "severity": "HIGH"},
        ]

    def match(self, event):
        matches = []
        for r in self.rules:
            watcher_match = "watcher" not in r or event.get("watcher") == r["watcher"]
            field_val = event.get(r["field"])
            if watcher_match and field_val is not None:
                if r["op"] == "==" and field_val == r["value"]:
                    matches.append(r)
                elif r["op"] == ">" and isinstance(field_val, (int, float)) and field_val > r["value"]:
                    matches.append(r)
        return matches


def classify(anomaly_result, rule_matches):
    if anomaly_result and anomaly_result.get("is_anomaly"):
        score = anomaly_result.get("anomaly_score", 0)
        if score > 75: return "CRITICAL"
        elif score > 50: return "HIGH"
        elif score > 25: return "MEDIUM"
        return "LOW"
    for m in rule_matches:
        if m.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
            return m["severity"]
    return "SAFE"


store = AlertStore()
anomaly_engine = AnomalyEngine()
rule_engine = RuleEngine()


def process_event(pillar, event):
    features = event.get("features", {})
    anomaly_result = anomaly_engine.update(pillar, features)
    rule_matches = rule_engine.match(event)
    severity = classify(anomaly_result, rule_matches)

    if severity == "SAFE" and not rule_matches:
        return None

    if severity == "SAFE" and rule_matches:
        severity = "HIGH"

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
            self._json_response({"status": "online", "uptime": time.time(), "version": "2.0.0", "watchers": ["process", "network", "hardware", "filesystem", "idle"], "anomaly_engine": "active", "model_status": {p: {"trained": p in anomaly_engine.models, "samples": anomaly_engine.sample_counts.get(p, 0)} for p in FEATURE_NAMES}})
        elif path == "/api/alerts":
            self._json_response(store.get_alerts(limit=50))
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
            self._json_response({"sensitivity": 0.5, "voice_enabled": True, "watcher_toggles": {p: True for p in FEATURE_NAMES}})
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
            result = process_event(body.get("pillar", "process"), body.get("event", {}))
            self._json_response({"processed": result is not None, "alert": result})
        elif path == "/api/simulate":
            pillar = body.get("pillar", "network")
            event = body.get("event", {"type": "NETWORK_SUSPICIOUS", "process_name": "unknown.exe", "pid": 0, "remote_ip": "45.33.32.156", "remote_port": 4444, "is_foreign_ip": True, "is_suspicious_port": True, "features": {"is_foreign_ip": 1.0, "is_suspicious_port": 1.0, "bytes_delta": 50000.0, "connection_count": 0.05, "port_number": 0.068}})
            result = process_event(pillar, event)
            self._json_response({"processed": result is not None, "alert": result})
        elif path == "/api/simulate/camera":
            result = process_event("hardware", {"type": "CAMERA_ACCESS", "process_name": body.get("app", "unknown.exe"), "pid": body.get("pid", 0), "is_first_time": True, "is_background": False, "is_signed": True, "app_is_known": False, "features": {"is_first_time": 1.0, "is_background": 0.0, "is_signed": 1.0, "app_is_known": 0.0}})
            self._json_response({"processed": result is not None, "alert": result})
        elif path == "/api/simulate/mic":
            result = process_event("hardware", {"type": "MIC_ACCESS", "process_name": body.get("app", "unknown.exe"), "pid": body.get("pid", 0), "is_first_time": True, "is_background": True, "is_signed": True, "app_is_known": False, "features": {"is_first_time": 1.0, "is_background": 1.0, "is_signed": 1.0, "app_is_known": 0.0}})
            self._json_response({"processed": result is not None, "alert": result})
        elif path == "/api/simulate/process":
            result = process_event("process", {"type": "PROCESS_SUSPICIOUS", "process_name": body.get("name", "malware.exe"), "pid": body.get("pid", 0), "is_unsigned": True, "from_temp": True, "parent_child_pair": True, "features": {"is_first_time": 1.0, "is_background": 1.0, "is_signed": 0.0, "thread_count": 0.8, "memory_usage": 0.7, "cpu_percent": 0.6, "handle_count": 0.3}})
            self._json_response({"processed": result is not None, "alert": result})
        elif path == "/api/simulate/ransomware":
            result = process_event("filesystem", {"type": "RANSOMWARE_BURST", "process_name": body.get("name", "locker.exe"), "pid": body.get("pid", 0), "features": {"write_burst": 0.9, "extension_entropy": 0.8, "rename_count": 0.7, "delete_count": 0.3, "file_count": 0.5}})
            self._json_response({"processed": result is not None, "alert": result})
        elif path == "/api/settings":
            self._json_response({"ok": True})
        elif path == "/api/actions/whitelist":
            store.whitelist.add(body.get("process_name", "").lower())
            self._json_response({"ok": True})
        elif path == "/api/actions/dismiss":
            for a in store.alerts:
                if a.get("id") == body.get("alert_id"): a["dismissed"] = 1
            self._json_response({"ok": True})
        elif path == "/api/actions/kill":
            self._json_response({"ok": True, "message": "Process kill not available on Vercel"})
        else:
            self._json_response({"error": "Not found"}, 404)

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/actions/whitelist/"):
            store.whitelist.discard(path.split("/")[-1].lower())
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
