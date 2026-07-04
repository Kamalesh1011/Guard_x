from pathlib import Path
import json

BASE_DIR = Path(__file__).parent.parent
AGENT_DIR = Path(__file__).parent
MODELS_DIR = AGENT_DIR / "models"
DB_PATH = BASE_DIR / "guardian.db"
RULES_PATH = AGENT_DIR / "rules.json"
ASSETS_DIR = BASE_DIR / "assets"


class Config:
    POLL_INTERVAL = 3
    BASELINE_SAMPLES = 200
    CONTAMINATION = 0.05
    RETRAIN_INTERVAL = 1000

    SEVERITY_THRESHOLDS = {
        "CRITICAL": 70,
        "HIGH": 50,
        "MEDIUM": 30,
        "LOW": 10,
    }

    RANSOMWARE_BURST_THRESHOLD = 10
    RANSOMWARE_EXTENSIONS = [
        ".encrypted", ".locked", ".cerber", ".crypt",
        ".enc", ".crypted", ".decrypt", ".ryk",
        ".wannacry", ".wncry", ".zepto", ".cerber3",
    ]

    SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 9001, 8080, 23, 1080, 5555, 7777}
    PRIVATE_IP_PREFIXES = ("192.168.", "10.", "172.16.", "127.", "::1")

    VOICE_RATE = 165
    VOICE_VOLUME = 0.95

    API_HOST = "127.0.0.1"
    API_PORT = 8001
    WS_BROADCAST_INTERVAL = 1

    IDLE_THRESHOLD_SECONDS = 300
    EWMA_ALPHA = 0.3

    PROCESS_FEATURES = [
        "cpu_percent", "memory_percent", "is_signed", "from_temp",
        "parent_child_pair", "has_window", "encoded_cmdline",
    ]
    NETWORK_FEATURES = [
        "is_foreign_ip", "is_suspicious_port", "bytes_delta",
        "connection_count", "port_number",
    ]
    HARDWARE_FEATURES = [
        "is_first_time", "is_background", "is_signed", "app_is_known",
    ]
    FILESYSTEM_FEATURES = [
        "events_per_3s", "has_ransomware_ext", "is_sensitive_path", "is_system_dir",
    ]
    IDLE_FEATURES = [
        "cpu_vs_baseline", "proc_count_vs_baseline",
        "network_vs_baseline", "unknown_proc_count",
    ]

    WATCHER_DEFAULTS = {
        "process": True,
        "network": True,
        "hardware": True,
        "filesystem": True,
        "idle": True,
    }

    SENSITIVE_PATHS = [
        "system32", "syswow64", "program files", "program files (x86)",
        "windows\\system32", "windows\\syswow64",
    ]

    SYSTEM_DIRS = [
        "c:\\windows\\system32", "c:\\windows\\syswow64",
        "c:\\windows\\servicing",
    ]

    SUSPICIOUS_PARENT_PAIRS = {
        "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"],
        "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
        "powerpnt.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
        "outlook.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
        "chrome.exe": ["cmd.exe", "powershell.exe"],
        "firefox.exe": ["cmd.exe", "powershell.exe"],
        "explorer.exe": ["powershell.exe", "cmd.exe"],
        "svchost.exe": ["cmd.exe", "powershell.exe"],
    }


config = Config()
