import time
import ctypes
import psutil
from agent.watchers.base_watcher import BaseWatcher


class IdleWatcher(BaseWatcher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.baselines = {
            "cpu": 5.0,
            "proc_count": 50,
            "network_bytes": 1000,
        }
        self.ewma_alpha = self.config.EWMA_ALPHA
        self.is_idle = False
        self.idle_start = 0
        self.unknown_pids = set()

    def _get_idle_seconds(self) -> int:
        try:
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.c_uint),
                    ("dwTime", ctypes.c_uint),
                ]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
            millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
            return millis // 1000
        except Exception:
            return 0

    def _update_baseline(self, metric: str, value: float):
        old = self.baselines.get(metric, value)
        self.baselines[metric] = self.ewma_alpha * value + (1 - self.ewma_alpha) * old

    def poll(self) -> dict:
        idle_secs = self._get_idle_seconds()
        was_idle = self.is_idle
        self.is_idle = idle_secs >= self.config.IDLE_THRESHOLD_SECONDS

        if not self.is_idle:
            if was_idle:
                self._snapshot_baseline()
            return {
                "cpu_vs_baseline": 0.0,
                "proc_count_vs_baseline": 0.0,
                "network_vs_baseline": 0.0,
                "unknown_proc_count": 0.0,
            }

        cpu = psutil.cpu_percent(interval=0.1)
        proc_count = len(psutil.pids())

        try:
            io = psutil.net_io_counters()
            net_bytes = io.bytes_sent + io.bytes_recv
        except Exception:
            net_bytes = 0

        self._update_baseline("cpu", cpu)
        self._update_baseline("proc_count", proc_count)
        self._update_baseline("network_bytes", net_bytes)

        cpu_ratio = cpu / max(self.baselines["cpu"], 1.0)
        proc_ratio = proc_count / max(self.baselines["proc_count"], 1.0)
        net_ratio = net_bytes / max(self.baselines["network_bytes"], 1.0)

        unknown_count = 0
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                if pid not in self.unknown_pids:
                    self.unknown_pids.add(pid)
                    unknown_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if len(self.unknown_pids) > 500:
            self.unknown_pids = set(list(self.unknown_pids)[-200:])

        features = {
            "cpu_vs_baseline": min(cpu_ratio, 10.0),
            "proc_count_vs_baseline": min(proc_ratio, 10.0),
            "network_vs_baseline": min(net_ratio, 10.0),
            "unknown_proc_count": float(unknown_count),
        }

        return features

    def _snapshot_baseline(self):
        self.baselines["cpu"] = psutil.cpu_percent(interval=0.1)
        self.baselines["proc_count"] = len(psutil.pids())
        try:
            io = psutil.net_io_counters()
            self.baselines["network_bytes"] = io.bytes_sent + io.bytes_recv
        except Exception:
            pass

    def build_events(self, features: dict, anomaly_result: dict) -> list:
        events = []
        if not self.is_idle:
            return events

        cpu_high = features.get("cpu_vs_baseline", 0) > 2.0
        unknown_high = features.get("unknown_proc_count", 0) > 3

        if cpu_high or unknown_high:
            severity = "HIGH" if (cpu_high and unknown_high) else "MEDIUM"
            events.append(
                self.emit(
                    {
                        "type": "IDLE_ANOMALY",
                        "process_name": "system",
                        "pid": None,
                        "severity": severity,
                        "cpu_vs_baseline": features.get("cpu_vs_baseline", 0),
                        "proc_count_vs_baseline": features.get("proc_count_vs_baseline", 0),
                        "network_vs_baseline": features.get("network_vs_baseline", 0),
                        "unknown_proc_count": features.get("unknown_proc_count", 0),
                    }
                )
            )

        return events
