import json
from datetime import datetime


SUSPICIOUS_PORTS = {
    4444: {"name": "Metasploit/Cobalt Strike", "risk": "CRITICAL", "ttp": "T1059.001 - Command and Scripting Interpreter: PowerShell", "description": "Port 4444 is the default listener for Metasploit framework and Cobalt Strike beacons. This is almost always malicious unless you are running a penetration test."},
    1337: {"name": "Waste/Backdoor", "risk": "HIGH", "ttp": "T1571 - Non-Standard Port", "description": "Port 1337 (leet) is commonly used by backdoors, trojans, and C2 frameworks to avoid detection by blending with normal traffic."},
    31337: {"name": "Back Orifice/BO2K", "risk": "CRITICAL", "ttp": "T1219 - Remote Access Software", "description": "Port 31337 is the classic Back Orifice trojan port. Any connection to this port indicates active malware compromise."},
    6666: {"name": "IRC Botnet/C2", "risk": "CRITICAL", "ttp": "T1071.001 - Application Layer Protocol: Web Protocols", "description": "Port 6666 is historically associated with IRC-based botnets and malware command channels. Active botnet communication suspected."},
    8080: {"name": "HTTP Proxy/Tunnel", "risk": "MEDIUM", "ttp": "T1090 - Proxy", "description": "Port 8080 is an alternate HTTP port often used by proxies, C2 tunnels, or data exfiltration channels."},
    23: {"name": "Telnet", "risk": "HIGH", "ttp": "T1021.004 - Remote Services: SSH", "description": "Telnet transmits credentials in plaintext. This connection may indicate lateral movement or credential theft."},
    1080: {"name": "SOCKS Proxy", "risk": "HIGH", "ttp": "T1090 - Proxy", "description": "SOCKS proxy detected. Attackers use this to tunnel traffic through compromised hosts and evade network monitoring."},
    5555: {"name": "Android Debug/Fastboot", "risk": "MEDIUM", "ttp": "T1200 - Hardware Additions", "description": "Port 5555 is used by Android Debug Bridge. May indicate device debugging or malicious app installation."},
    7777: {"name": "Trojan/Games", "risk": "MEDIUM", "ttp": "T1571 - Non-Standard Port", "description": "Port 7777 is commonly used by trojans and game cheats that open backdoors."},
    9001: {"name": "Tor SOCKS", "risk": "HIGH", "ttp": "T1090.003 - Proxy: Multi-hop Proxy", "description": "Tor network proxy detected. This is used to anonymize malicious traffic and bypass security controls."},
}

FOREIGN_IP_CONTEXT = {
    "known_malicious": {
        "ranges": ["45.33.32.", "185.220.101.", "198.51.100.", "203.0.113."],
        "description": "This IP range is associated with known threat actors and has been flagged in multiple threat intelligence feeds.",
    },
    "bulletproof_hosting": {
        "ranges": ["194.26.29.", "91.215.85.", "185.56.80."],
        "description": "This IP belongs to a bulletproof hosting provider known for sheltering criminal infrastructure and ignoring abuse complaints.",
    },
    "cloud_vps": {
        "ranges": ["35.", "52.", "34.", "54.", "18.161.", "18.216.", "13.", "3.173.", "18.136.", "103.28."],
        "description": "This IP is from a cloud VPS provider. Legitimate services use these, but so do attackers for C2 servers and payload delivery.",
    },
    "residential": {
        "ranges": ["192.168.", "10.", "172.16."],
        "description": "This is a local/private IP address.",
    },
}

PROCESS_RISK_SIGNALS = {
    "unsigned_child": "The child process is not digitally signed, which is a strong indicator of malware. Legitimate software is almost always signed.",
    "from_temp": "The process is running from a temporary directory. Malware commonly drops payloads in temp folders to evade application whitelisting.",
    "parent_child_mismatch": "The parent-child process relationship is unusual. For example, Word spawning PowerShell is a classic macro malware pattern.",
    "encoded_cmdline": "The command line contains Base64-encoded or obfuscated content. This is a hallmark of fileless malware and living-off-the-land attacks.",
    "high_thread_count": "Abnormally high thread count indicates the process may be performing brute-force attacks, cryptomining, or parallel payload execution.",
    "high_memory": "Unusual memory consumption suggests the process may be running injected code, performing credential dumping, or has loaded a malicious DLL.",
    "no_window": "A process with no visible window running background operations is suspicious. Legitimate background services are usually signed and well-known.",
    "injected_code": "Memory pattern analysis suggests code injection. The process may have injected malicious shellcode into a legitimate process.",
}

CAMERA_MIC_CONTEXT = {
    "surveillance": "Unauthorized camera/microphone access is a primary indicator of surveillance malware, stalkerware, or remote access trojans (RATs).",
    "data_exfil": "Audio/video data can be captured and exfiltrated without your knowledge. This data may be used for blackmail, espionage, or identity theft.",
    "privacy_violation": "Even if the access is from a legitimate app, background access without your explicit action violates privacy best practices.",
    "rat_indicator": "RATs like njRAT, DarkComet, and Quasar routinely abuse camera/microphone for remote surveillance of victims.",
}

RANSOMWARE_INDICATORS = {
    "burst_write": "Rapid file modification in short timeframes is the primary behavioral indicator of ransomware encryption.",
    "extension_change": "Files being renamed with unknown extensions (e.g., .locked, .encrypted, .crypto) confirms active encryption.",
    "shadow_copy_delete": "Deletion of Volume Shadow Copies prevents file recovery. This is a deliberate anti-forensics technique.",
    "note_drop": "Ransom notes being dropped in multiple directories indicates the encryption phase is complete and extortion has begun.",
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
        risk_factors.append({
            "factor": f"Suspicious Port {port}",
            "contribution": shap_values.get("is_suspicious_port", 0),
            "detail": port_info["description"],
            "ttp": port_info["ttp"],
            "risk_level": port_info["risk"],
        })
        total_risk += abs(shap_values.get("is_suspicious_port", 0))

    if is_foreign:
        ip_class = "cloud_vps"
        ip_desc = "Foreign IP detected."
        for cls, info in FOREIGN_IP_CONTEXT.items():
            for prefix in info["ranges"]:
                if ip.startswith(prefix):
                    ip_class = cls
                    ip_desc = info["description"]
                    break

        risk_factors.append({
            "factor": "Foreign IP Connection",
            "contribution": shap_values.get("is_foreign_ip", 0),
            "detail": ip_desc,
            "ttp": "T1071 - Application Layer Protocol",
            "risk_level": "HIGH" if ip_class in ("known_malicious", "bulletproof_hosting") else "MEDIUM",
        })
        total_risk += abs(shap_values.get("is_foreign_ip", 0))

    bytes_delta = shap_values.get("bytes_delta", 0)
    if bytes_delta > 0.3:
        risk_factors.append({
            "factor": "High Data Transfer",
            "contribution": bytes_delta,
            "detail": "Abnormally high bytes transferred. This may indicate data exfiltration, payload download, or C2 keepalive traffic.",
            "ttp": "T1041 - Exfiltration Over C2 Channel",
            "risk_level": "HIGH" if bytes_delta > 0.5 else "MEDIUM",
        })
        total_risk += abs(bytes_delta)

    if anomaly_score > 75:
        risk_factors.append({
            "factor": "Anomaly Score",
            "contribution": anomaly_score / 100,
            "detail": f"The machine learning model flagged this connection with {anomaly_score:.0f}/100 anomaly score based on historical behavior patterns.",
            "ttp": "Behavioral Analysis",
            "risk_level": "CRITICAL" if anomaly_score > 90 else "HIGH",
        })

    severity = "CRITICAL" if total_risk > 1.5 or anomaly_score > 85 else "HIGH" if total_risk > 0.8 else "MEDIUM"

    summary = f"{proc} established an outbound connection to {ip}:{port}."
    if port_info:
        summary += f" Port {port} is associated with {port_info['name']}."
    if is_foreign:
        summary += f" The destination is outside your local network."

    recommendation = f"Investigate {proc} immediately. "
    if port_info and port_info["risk"] == "CRITICAL":
        recommendation += f"Port {port} ({port_info['name']}) is a known malicious indicator. "
    recommendation += f"Check the process origin, command line arguments, and network behavior. If unauthorized, block {ip} in your firewall and terminate {proc}."

    return {
        "summary": summary,
        "risk_factors": risk_factors,
        "total_risk_score": round(total_risk, 2),
        "severity": severity,
        "recommendation": recommendation,
        "mitre_ttps": [rf["ttp"] for rf in risk_factors if rf.get("ttp")],
    }


def explain_camera_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    is_first = event.get("is_first_time", False)
    is_bg = event.get("is_background", False)
    is_known = event.get("app_is_known", False)

    risk_factors = []

    if is_first:
        risk_factors.append({
            "factor": "First-Time Camera Access",
            "contribution": shap_values.get("is_first_time", 0),
            "detail": f"{proc} has never accessed your camera before in the monitored period. New camera access by an unknown application is a critical privacy concern.",
            "ttp": "T1125 - Video Capture",
            "risk_level": "HIGH",
        })

    if is_bg:
        risk_factors.append({
            "factor": "Background Access",
            "contribution": shap_values.get("is_background", 0),
            "detail": f"{proc} accessed your camera while running in the background with no visible window. Legitimate apps require user interaction to access the camera.",
            "ttp": "T1203 - Exploitation for Client Execution",
            "risk_level": "CRITICAL",
        })

    if not is_known:
        risk_factors.append({
            "factor": "Untrusted Application",
            "contribution": shap_values.get("app_is_known", 0),
            "detail": f"{proc} is not in your trusted application list. This application has not been verified or approved for camera access.",
            "ttp": "T1200 - Hardware Additions",
            "risk_level": "MEDIUM",
        })

    summary = f"Your integrated camera was activated by {proc}."
    if is_first:
        summary += " This is the first time this application has accessed your camera."
    if is_bg:
        summary += " The application is running in the background."

    risk_detail = CAMERA_MIC_CONTEXT["surveillance"]
    recommendation = f"Verify if {proc} is an application you trust. "
    if is_bg:
        recommendation += "The background access pattern is suspicious. "
    recommendation += f"If you did not initiate camera use, terminate {proc} immediately via Task Manager. "
    recommendation += "Check Camera privacy settings in Windows to revoke access for unknown apps."

    return {
        "summary": summary,
        "risk_factors": risk_factors,
        "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2),
        "severity": "CRITICAL" if is_bg else "HIGH",
        "recommendation": recommendation,
        "mitre_ttps": [rf["ttp"] for rf in risk_factors],
        "threat_context": risk_detail,
    }


def explain_mic_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    is_first = event.get("is_first_time", False)
    is_bg = event.get("is_background", False)
    is_known = event.get("app_is_known", False)

    risk_factors = []

    if is_first:
        risk_factors.append({
            "factor": "First-Time Microphone Access",
            "contribution": shap_values.get("is_first_time", 0),
            "detail": f"{proc} has never used your microphone before. Unauthorized audio capture is a primary vector for espionage and data theft.",
            "ttp": "T1123 - Audio Capture",
            "risk_level": "HIGH",
        })

    if is_bg:
        risk_factors.append({
            "factor": "Silent Background Recording",
            "contribution": shap_values.get("is_background", 0),
            "detail": f"{proc} is capturing audio while hidden. This is the exact behavior pattern of spyware and RATs like njRAT and DarkComet.",
            "ttp": "T1123 - Audio Capture",
            "risk_level": "CRITICAL",
        })

    summary = f"Your microphone is being used by {proc}."
    if is_first:
        summary += " This application has never accessed your microphone before."
    if is_bg:
        summary += " The application is running in the background without a visible interface."

    recommendation = f"Investigate {proc}. "
    if is_bg:
        recommendation += "Background microphone access without user interaction is highly suspicious. "
    recommendation += f"Open Sound Settings to see which app is using the microphone. If {proc} is unknown, terminate it and run a full malware scan."

    return {
        "summary": summary,
        "risk_factors": risk_factors,
        "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2),
        "severity": "CRITICAL" if is_bg else "HIGH",
        "recommendation": recommendation,
        "mitre_ttps": [rf["ttp"] for rf in risk_factors],
        "threat_context": CAMERA_MIC_CONTEXT["rat_indicator"],
    }


def explain_process_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    risk_factors = []

    signals = {
        "is_unsigned": "The process lacks a valid digital signature. Unsigned executables are a primary indicator of malware.",
        "from_temp": "The process is executing from a temporary directory. This is a common malware evasion technique.",
        "parent_child_pair": "The process was spawned by an unexpected parent. This parent-child anomaly often indicates script-based malware execution.",
        "has_window": "The process has no visible user interface, suggesting it is designed to run silently in the background.",
        "encoded_cmdline": "The command line contains encoded content. Attackers encode commands to bypass security tools and evade detection.",
    }

    for key, detail in signals.items():
        val = shap_values.get(key, 0)
        if val > 0.1:
            risk_factors.append({
                "factor": key.replace("_", " ").title(),
                "contribution": val,
                "detail": detail,
                "ttp": "T1059 - Command and Scripting Interpreter",
                "risk_level": "HIGH",
            })

    cpu = shap_values.get("cpu_percent", 0)
    mem = shap_values.get("memory_usage", 0)
    if cpu > 0.4:
        risk_factors.append({
            "factor": "CPU Anomaly",
            "contribution": cpu,
            "detail": "Abnormal CPU usage detected. This may indicate cryptomining, brute-force attacks, or payload execution.",
            "ttp": "T1496 - Resource Hijacking",
            "risk_level": "MEDIUM",
        })
    if mem > 0.4:
        risk_factors.append({
            "factor": "Memory Anomaly",
            "contribution": mem,
            "detail": "Abnormal memory consumption suggests possible code injection, credential dumping, or reflective DLL loading.",
            "ttp": "T1055 - Process Injection",
            "risk_level": "HIGH",
        })

    summary = f"Suspicious process detected: {proc}."
    if risk_factors:
        summary += f" {len(risk_factors)} risk indicators identified."

    recommendation = f"Review {proc} in Task Manager. Check its file location, digital signature, and command line. "
    recommendation += "If the process is unknown or behaving abnormally, terminate it and run a full antivirus scan."

    return {
        "summary": summary,
        "risk_factors": risk_factors,
        "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2),
        "severity": "CRITICAL" if len(risk_factors) >= 3 else "HIGH" if len(risk_factors) >= 2 else "MEDIUM",
        "recommendation": recommendation,
        "mitre_ttps": list(set(rf["ttp"] for rf in risk_factors)),
    }


def explain_ransomware_event(event, shap_values, anomaly_score):
    proc = event.get("process_name", "unknown")
    risk_factors = []

    write_burst = shap_values.get("write_burst", 0)
    ext_change = shap_values.get("extension_entropy", 0)
    rename_count = shap_values.get("rename_count", 0)
    delete_count = shap_values.get("delete_count", 0)

    if write_burst > 0.3:
        risk_factors.append({
            "factor": "Rapid File Encryption",
            "contribution": write_burst,
            "detail": RANSOMWARE_INDICATORS["burst_write"],
            "ttp": "T1486 - Data Encrypted for Impact",
            "risk_level": "CRITICAL",
        })

    if ext_change > 0.3:
        risk_factors.append({
            "factor": "File Extension Tampering",
            "contribution": ext_change,
            "detail": RANSOMWARE_INDICATORS["extension_change"],
            "ttp": "T1486 - Data Encrypted for Impact",
            "risk_level": "CRITICAL",
        })

    if rename_count > 0.3:
        risk_factors.append({
            "factor": "Mass File Renaming",
            "contribution": rename_count,
            "detail": RANSOMWARE_INDICATORS["note_drop"],
            "ttp": "T1486 - Data Encrypted for Impact",
            "risk_level": "CRITICAL",
        })

    summary = f"Ransomware behavior detected from {proc}."
    if risk_factors:
        summary += f" {len(risk_factors)} encryption indicators active."

    recommendation = "DISCONNECT FROM THE NETWORK IMMEDIATELY. "
    recommendation += "Do not restart the computer. "
    recommendation += "Check for ransom notes in affected directories. "
    recommendation += "Use ransomware decryption tools from nomoreransom.org if available. "
    recommendation += "Report to your security team and consider forensic analysis."

    return {
        "summary": summary,
        "risk_factors": risk_factors,
        "total_risk_score": round(sum(abs(rf["contribution"]) for rf in risk_factors), 2),
        "severity": "CRITICAL",
        "recommendation": recommendation,
        "mitre_ttps": ["T1486 - Data Encrypted for Impact"],
        "threat_context": "Ransomware is the most destructive form of malware. Immediate isolation is critical to prevent lateral spread.",
    }


EXPLAINERS = {
    "NETWORK_SUSPICIOUS": explain_network_event,
    "CAMERA_ACCESS": explain_camera_event,
    "MIC_ACCESS": explain_mic_event,
    "PROCESS_SUSPICIOUS": explain_process_event,
    "RANSOMWARE_BURST": explain_ransomware_event,
}


def explain(event, anomaly_result=None):
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

    return {
        "summary": f"Event detected: {event_type} from {event.get('process_name', 'unknown')}.",
        "risk_factors": [],
        "total_risk_score": 0,
        "severity": event.get("severity", "MEDIUM"),
        "recommendation": "Review this event and take action if needed.",
        "shap_values": shap_values,
        "anomaly_score": anomaly_score,
        "mitre_ttps": [],
    }
