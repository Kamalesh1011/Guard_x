import asyncio
import json
import threading
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self._lock:
            self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        with self._lock:
            targets = list(self.active_connections)
        dead = []
        for connection in targets:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        if dead:
            with self._lock:
                for d in dead:
                    if d in self.active_connections:
                        self.active_connections.remove(d)

    def broadcast_sync(self, message: dict):
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(asyncio.ensure_future, self.broadcast(message))
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self.broadcast(message))
                else:
                    loop.run_until_complete(self.broadcast(message))
            except Exception:
                pass


ws_manager = ConnectionManager()


def create_app(agent=None):
    app = FastAPI(title="GUARDIAN API", version="1.0.0")
    app.state.ws_manager = ws_manager
    app.state.agent = agent

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.websocket("/ws/events")
    async def websocket_endpoint(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    @app.get("/api/status")
    def get_status():
        if not agent:
            return {"status": "no agent"}
        stats = agent.db.get_alert_stats()

        recent_alerts = agent.db.get_alerts(limit=50)
        active_alerts = [a for a in recent_alerts if not a.get("dismissed")]

        threat = "SAFE"
        for alert in active_alerts:
            sev = alert.get("severity", "SAFE")
            if sev == "CRITICAL":
                threat = "CRITICAL"
                break
            elif sev == "HIGH" and threat != "CRITICAL":
                threat = "HIGH"
            elif sev == "MEDIUM" and threat not in ("CRITICAL", "HIGH"):
                threat = "MEDIUM"
            elif sev == "LOW" and threat not in ("CRITICAL", "HIGH", "MEDIUM"):
                threat = "LOW"

        elapsed = time.time() - agent._start_time if hasattr(agent, "_start_time") else 0
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)

        return {
            "watchers": agent.watcher_toggles,
            "threat_level": threat,
            "model_status": agent.anomaly_engine.get_model_status(),
            "uptime": f"{hours}h {minutes}m",
            "alert_stats": stats,
        }

    @app.get("/api/alerts")
    def get_alerts(limit: int = 50, offset: int = 0, severity: str = None):
        if not agent:
            return []
        return agent.db.get_alerts(limit=limit, offset=offset, severity=severity)

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: int):
        if not agent:
            return None
        return agent.db.get_alert(alert_id)

    @app.get("/api/hardware")
    def get_hardware():
        if not agent:
            return {}
        for pillar, watcher in agent._watchers:
            if pillar == "hardware":
                return watcher.get_hardware_status()
        return {"camera": {"active": False, "apps": []}, "microphone": {"active": False, "apps": []}}

    @app.get("/api/processes")
    def get_processes():
        import psutil
        nodes = []
        edges = []
        for proc in psutil.process_iter(["pid", "name", "ppid", "cpu_percent", "memory_percent"]):
            try:
                info = proc.info
                nodes.append({
                    "id": info["pid"],
                    "name": info.get("name", "unknown"),
                    "cpu": info.get("cpu_percent", 0) or 0,
                    "memory": info.get("memory_percent", 0) or 0,
                })
                ppid = info.get("ppid", 0)
                if ppid:
                    edges.append({"source": ppid, "target": info["pid"]})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return {"nodes": nodes, "edges": edges}

    @app.get("/api/network")
    def get_network():
        import psutil
        connections = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                proc_name = "unknown"
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                connections.append({
                    "pid": conn.pid,
                    "process_name": proc_name,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                })
        return connections

    @app.get("/api/settings")
    def get_settings():
        if not agent:
            return {}
        settings = agent.db.get_all_settings()
        settings["poll_interval"] = str(agent.poll_interval)
        settings["contamination"] = str(agent.contamination)
        for pillar in agent.watcher_toggles:
            settings[f"watcher_{pillar}"] = str(agent.watcher_toggles[pillar])
        return settings

    @app.post("/api/settings")
    def update_settings(data: dict):
        if not agent:
            return {"error": "no agent"}
        for key, value in data.items():
            agent.db.set_setting(key, str(value))
            if key == "poll_interval":
                agent.poll_interval = int(value)
            elif key == "contamination":
                agent.contamination = float(value)
            elif key.startswith("watcher_"):
                pillar = key.replace("watcher_", "")
                agent.watcher_toggles[pillar] = value.lower() == "true"
        return {"status": "ok"}

    @app.post("/api/actions/whitelist")
    def add_whitelist(data: dict):
        if not agent:
            return {"error": "no agent"}
        name = data.get("process_name", "")
        if name:
            agent.db.add_to_whitelist(name)
            agent.refresh_whitelist()
        return {"status": "ok"}

    @app.delete("/api/actions/whitelist/{process_name}")
    def remove_whitelist(process_name: str):
        if not agent:
            return {"error": "no agent"}
        agent.db.remove_from_whitelist(process_name)
        agent.refresh_whitelist()
        return {"status": "ok"}

    @app.get("/api/whitelist")
    def get_whitelist():
        if not agent:
            return []
        return agent.db.get_whitelist_all()

    @app.post("/api/actions/kill")
    def kill_process(data: dict):
        import psutil
        pid = data.get("pid")
        if not pid:
            return {"error": "no pid"}
        try:
            psutil.Process(pid).kill()
            return {"status": "ok", "pid": pid}
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"error": str(e)}

    @app.post("/api/actions/dismiss")
    def dismiss_alert(data: dict):
        if not agent:
            return {"error": "no agent"}
        alert_id = data.get("alert_id")
        if alert_id:
            agent.db.dismiss_alert(alert_id)
        return {"status": "ok"}

    @app.get("/api/export/csv")
    def export_csv():
        import csv
        import io
        from fastapi.responses import StreamingResponse

        if not agent:
            return {"error": "no agent"}
        alerts = agent.db.get_alerts(limit=10000)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "id", "type", "process_name", "pid", "severity",
            "summary", "recommendation", "created_at"
        ])
        writer.writeheader()
        for alert in alerts:
            writer.writerow({k: alert.get(k, "") for k in [
                "id", "type", "process_name", "pid", "severity",
                "summary", "recommendation", "created_at"
            ]})
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=guardian_alerts.csv"},
        )

    @app.get("/api/stats")
    def get_stats():
        if not agent:
            return {}
        return agent.db.get_alert_stats()

    return app


import time
