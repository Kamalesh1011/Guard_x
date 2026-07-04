EXPLANATION_TEMPLATES = {
    "UNKNOWN_PROCESS": {
        "base": "An unknown process started: {process_name}.",
        "reasons": {
            "is_unsigned": "The executable is not digitally signed.",
            "from_temp": "It is running from a temporary folder.",
            "parent_child_pair": "It was spawned by an unexpected parent process.",
            "has_window": "It has no visible window.",
            "encoded_cmdline": "The command line contains encoded or obfuscated content.",
            "cpu_percent": "The process is using abnormal CPU resources.",
            "memory_percent": "The process has unusual memory usage.",
        },
    },
    "NETWORK_SUSPICIOUS": {
        "base": "{process_name} opened a connection to {remote_ip}:{remote_port}.",
        "reasons": {
            "is_suspicious_port": "The destination port is commonly used by attack frameworks.",
            "is_foreign_ip": "The destination IP is outside your local network.",
            "bytes_delta": "Unusually high data transfer was detected.",
            "connection_count": "There are an unusual number of active connections.",
        },
    },
    "CAMERA_ACCESS": {
        "base": "Your camera was accessed by {process_name}.",
        "reasons": {
            "is_first_time": "This application has never accessed your camera before.",
            "is_background": "It accessed the camera while running in the background.",
            "is_signed": "The executable is not digitally signed.",
            "app_is_known": "This app is not in your trusted list.",
        },
    },
    "MIC_ACCESS": {
        "base": "Your microphone is now active. Process responsible: {process_name}.",
        "reasons": {
            "is_first_time": "This application has never accessed your microphone before.",
            "is_background": "It accessed the microphone while running in the background.",
            "app_is_known": "This app is not in your trusted list.",
        },
    },
    "RANSOMWARE_BURST": {
        "base": "File system activity indicates possible ransomware behavior.",
        "reasons": {
            "events_per_3s": "{events_per_3s} files were modified in 3 seconds.",
            "has_ransomware_ext": "Files with known ransomware extensions were detected.",
            "is_sensitive_path": "Modifications occurred in a sensitive system path.",
            "is_system_dir": "Files in a Windows system directory were modified.",
        },
    },
    "IDLE_ANOMALY": {
        "base": "Unusual activity detected while the system was idle.",
        "reasons": {
            "cpu_vs_baseline": "CPU usage is {cpu_vs_baseline}x higher than the idle baseline.",
            "proc_count_vs_baseline": "Process count is {proc_count_vs_baseline}x higher than baseline.",
            "network_vs_baseline": "Network activity is {network_vs_baseline}x higher than baseline.",
            "unknown_proc_count": "{unknown_proc_count} unknown processes are active.",
        },
    },
    "SCREEN_CAPTURE": {
        "base": "{process_name} is capturing your screen.",
        "reasons": {
            "is_unsigned": "The executable is not digitally signed.",
            "is_background": "It is running silently without a visible window.",
        },
    },
    "KEYBOARD_HOOK": {
        "base": "A keyboard hook was detected from {process_name}.",
        "reasons": {
            "is_unsigned": "The executable is not digitally signed.",
            "is_background": "It is running in the background.",
        },
    },
    "USB_INSERT": {
        "base": "A USB device was connected: {device}.",
        "reasons": {
            "is_first_time": "This device has never been connected before.",
        },
    },
    "BLUETOOTH_CONNECT": {
        "base": "Bluetooth device {device} connected.",
        "reasons": {
            "is_first_time": "This device is not in your paired devices history.",
        },
    },
}

RECOMMENDATIONS = {
    "UNKNOWN_PROCESS": "Open Task Manager and terminate PID {pid}. Check recently installed software.",
    "NETWORK_SUSPICIOUS": "Block {process_name} in Windows Firewall. The connection may be unauthorized.",
    "CAMERA_ACCESS": "If you did not open a video app, terminate {process_name} immediately via Task Manager.",
    "MIC_ACCESS": "Verify if a call or recording app is open. If unexpected, terminate the process.",
    "RANSOMWARE_BURST": "Disconnect from network immediately. Do not restart. Isolate the machine.",
    "IDLE_ANOMALY": "Check Task Manager for unexpected processes running while the system is idle.",
    "SCREEN_CAPTURE": "Confirm if you authorized screen sharing. If not, close the application.",
    "KEYBOARD_HOOK": "Immediately check if this is a known app. If unfamiliar, terminate and run a malware scan.",
    "USB_INSERT": "Safely eject the device if you did not plug it in yourself.",
    "BLUETOOTH_CONNECT": "Disconnect this device from Bluetooth settings if unrecognized.",
}


class XAIEngine:
    def __init__(self, config=None):
        self.config = config

    def explain(self, event: dict, anomaly_result: dict = None) -> dict:
        event_type = event.get("type", "UNKNOWN")
        template = EXPLANATION_TEMPLATES.get(event_type, {})

        base = template.get("base", "")
        try:
            base_text = base.format(**event)
        except KeyError:
            base_text = base

        active_reasons = []
        reason_templates = template.get("reasons", {})

        for key, reason_text in reason_templates.items():
            value = event.get(key)
            if self._is_reason_active(key, value):
                try:
                    formatted = reason_text.format(**event)
                except KeyError:
                    formatted = reason_text
                active_reasons.append(formatted)

        shap_values = {}
        if anomaly_result and anomaly_result.get("shap_values"):
            shap_values = anomaly_result["shap_values"]

        top_shap = self._get_top_shap_reasons(shap_values)
        for reason in top_shap:
            if reason["text"] not in active_reasons:
                active_reasons.insert(0, reason["text"])

        active_reasons = active_reasons[:5]

        full_summary = base_text
        if active_reasons:
            full_summary += " " + " ".join(active_reasons)

        recommendation = RECOMMENDATIONS.get(event_type, "Review this event and take action if needed.")
        try:
            recommendation = recommendation.format(**event)
        except KeyError:
            pass

        return {
            "summary": full_summary,
            "reasons": active_reasons,
            "shap_values": shap_values,
            "recommendation": recommendation,
            "threat_level": event.get("severity", "MEDIUM"),
        }

    def _is_reason_active(self, key: str, value) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if key == "events_per_3s":
                return value >= 10
            if key == "cpu_vs_baseline":
                return value >= 2.0
            if key == "proc_count_vs_baseline":
                return value >= 1.5
            if key == "network_vs_baseline":
                return value >= 2.0
            if key == "unknown_proc_count":
                return value >= 3
            return value > 0
        if isinstance(value, str):
            return len(value) > 0 and value.lower() not in ("unknown", "none", "")
        return bool(value)

    def _get_top_shap_reasons(self, shap_values: dict) -> list:
        if not shap_values:
            return []

        sorted_features = sorted(
            shap_values.items(),
            key=lambda x: abs(x[1]),
            reverse=True,
        )

        reasons = []
        for feature, contribution in sorted_features[:3]:
            if abs(contribution) < 0.01:
                continue
            direction = "suspicious" if contribution > 0 else "normal"
            weight_pct = round(abs(contribution) * 100, 1)
            readable = feature.replace("_", " ").replace("is ", "").replace("has ", "")
            text = f"{readable} contributes {weight_pct}% toward suspicion."
            reasons.append({
                "feature": feature,
                "contribution": contribution,
                "direction": direction,
                "weight_pct": weight_pct,
                "text": text,
            })

        return reasons
