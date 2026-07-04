import os
import time
from collections import deque
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from agent.watchers.base_watcher import BaseWatcher


RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".cerber", ".crypt",
    ".enc", ".crypted", ".decrypt", ".ryk",
    ".wannacry", ".wncry", ".zepto", ".cerber3",
    ".cerber2", ".crypto", ".ccc", ".vvv",
}

SENSITIVE_PATHS = [
    "system32", "syswow64", "program files", "program files (x86)",
    "windows\\system32", "windows\\syswow64",
]

SYSTEM_DIRS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\servicing",
]


class _BurstHandler(FileSystemEventHandler):
    def __init__(self, watcher):
        self.watcher = watcher

    def on_modified(self, event):
        if not event.is_directory:
            self.watcher._record_event(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.watcher._record_event(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.watcher._record_event(event.dest_path)


class FilesystemWatcher(BaseWatcher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.recent_events = deque()
        self.window_seconds = 3
        self.observer = None
        self._burst_threshold = self.config.RANSOMWARE_BURST_THRESHOLD

    def start_monitoring(self, paths: list = None):
        if self.observer is not None:
            return

        if paths is None:
            paths = [
                os.path.expanduser("~\\Documents"),
                os.path.expanduser("~\\Desktop"),
                os.path.expanduser("~\\Downloads"),
            ]

        self.observer = Observer()
        handler = _BurstHandler(self)
        for path in paths:
            if os.path.exists(path):
                try:
                    self.observer.schedule(handler, path, recursive=True)
                except Exception:
                    pass
        self.observer.start()

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None

    def _record_event(self, filepath: str):
        now = time.time()
        self.recent_events.append((now, filepath))
        while self.recent_events and self.recent_events[0][0] < now - self.window_seconds:
            self.recent_events.popleft()

    def poll(self) -> dict:
        now = time.time()
        while self.recent_events and self.recent_events[0][0] < now - self.window_seconds:
            self.recent_events.popleft()

        events_in_window = list(self.recent_events)
        count = len(events_in_window)

        has_ransomware_ext = False
        is_sensitive = False
        is_system = False

        for _, filepath in events_in_window:
            ext = Path(filepath).suffix.lower()
            if ext in RANSOMWARE_EXTENSIONS:
                has_ransomware_ext = True

            path_lower = filepath.lower()
            if any(s in path_lower for s in SENSITIVE_PATHS):
                is_sensitive = True
            if any(path_lower.startswith(s) for s in SYSTEM_DIRS):
                is_system = True

        features = {
            "events_per_3s": float(count),
            "has_ransomware_ext": 1.0 if has_ransomware_ext else 0.0,
            "is_sensitive_path": 1.0 if is_sensitive else 0.0,
            "is_system_dir": 1.0 if is_system else 0.0,
        }

        return features

    def build_events(self, features: dict, anomaly_result: dict) -> list:
        events = []
        count = features.get("events_per_3s", 0)

        if count >= self._burst_threshold or features.get("has_ransomware_ext", 0) > 0:
            severity = "CRITICAL" if features.get("has_ransomware_ext", 0) > 0 else "HIGH"
            events.append(
                self.emit(
                    {
                        "type": "RANSOMWARE_BURST",
                        "process_name": "filesystem",
                        "pid": None,
                        "severity": severity,
                        "events_per_3s": count,
                        "has_ransomware_ext": features.get("has_ransomware_ext", 0) > 0,
                        "is_sensitive_path": features.get("is_sensitive_path", 0) > 0,
                        "is_system_dir": features.get("is_system_dir", 0) > 0,
                    }
                )
            )
        elif features.get("is_system_dir", 0) > 0 and count > 3:
            events.append(
                self.emit(
                    {
                        "type": "RANSOMWARE_BURST",
                        "process_name": "filesystem",
                        "pid": None,
                        "severity": "MEDIUM",
                        "events_per_3s": count,
                        "has_ransomware_ext": False,
                        "is_sensitive_path": True,
                        "is_system_dir": True,
                    }
                )
            )

        return events
