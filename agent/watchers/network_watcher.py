import psutil
from agent.watchers.base_watcher import BaseWatcher


SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 9001, 8080, 23, 1080, 5555, 7777}
PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "127.", "::1")


def _is_foreign_ip(ip: str) -> bool:
    return not any(ip.startswith(p) for p in PRIVATE_PREFIXES)


class NetworkWatcher(BaseWatcher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.seen_connections = set()
        self.prev_bytes = {}
        self._suspicious_conns = []

    def poll(self) -> dict:
        features = {
            "is_foreign_ip": 0.0,
            "is_suspicious_port": 0.0,
            "bytes_delta": 0.0,
            "connection_count": 0.0,
            "port_number": 0.0,
        }

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return features

        established = [c for c in connections if c.status == "ESTABLISHED" and c.raddr]
        total = len(established) or 1
        foreign_count = 0
        suspicious_count = 0
        max_port = 0
        self._suspicious_conns = []

        for conn in established:
            ip = conn.raddr.ip
            port = conn.raddr.port
            key = (conn.pid, ip, port)

            if key in self.seen_connections:
                continue
            self.seen_connections.add(key)

            is_foreign = _is_foreign_ip(ip)
            is_sus_port = port in SUSPICIOUS_PORTS

            if is_foreign:
                foreign_count += 1
            if is_sus_port:
                suspicious_count += 1
            max_port = max(max_port, port)

            if is_foreign or is_sus_port:
                proc_name = "unknown"
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                self._suspicious_conns.append({
                    "pid": conn.pid,
                    "process_name": proc_name,
                    "remote_ip": ip,
                    "remote_port": port,
                    "is_foreign_ip": is_foreign,
                    "is_suspicious_port": is_sus_port,
                })

        try:
            io = psutil.net_io_counters()
            current_bytes = io.bytes_sent + io.bytes_recv
            prev = self.prev_bytes.get("total", current_bytes)
            features["bytes_delta"] = float(current_bytes - prev)
            self.prev_bytes["total"] = current_bytes
        except Exception:
            pass

        features["is_foreign_ip"] = foreign_count / total
        features["is_suspicious_port"] = suspicious_count / total
        features["connection_count"] = len(established) / 100.0
        features["port_number"] = max_port / 65535.0

        if len(self.seen_connections) > 10000:
            self.seen_connections = set(list(self.seen_connections)[-5000:])

        return features

    def build_events(self, features: dict, anomaly_result: dict) -> list:
        events = []
        for conn in self._suspicious_conns:
            severity = "HIGH" if conn["is_suspicious_port"] else "MEDIUM"
            events.append(
                self.emit(
                    {
                        "type": "NETWORK_SUSPICIOUS",
                        "process_name": conn["process_name"],
                        "pid": conn["pid"],
                        "severity": severity,
                        "remote_ip": conn["remote_ip"],
                        "remote_port": conn["remote_port"],
                        "is_foreign_ip": conn["is_foreign_ip"],
                        "is_suspicious_port": conn["is_suspicious_port"],
                    }
                )
            )
        return events
