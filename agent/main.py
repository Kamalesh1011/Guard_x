import sys
import os
import time
import json
import threading
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.config import config, BASE_DIR, DB_PATH, MODELS_DIR
from agent.storage.db import Database
from agent.voice.speaker import JarvisVoice

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(BASE_DIR / "guardian.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("guardian")


class GuardianAgent:
    def __init__(self):
        self.db = Database(str(DB_PATH))
        self.voice = JarvisVoice(rate=config.VOICE_RATE, volume=config.VOICE_VOLUME)
        self.whitelist = self.db.get_whitelist()
        self._watchers = []
        self._running = False
        self._ws_broadcast_fn = None

        self._load_settings()

    def _load_settings(self):
        self.poll_interval = int(self.db.get_setting("poll_interval", config.POLL_INTERVAL))
        self.contamination = float(self.db.get_setting("contamination", config.CONTAMINATION))
        self.watcher_toggles = {}
        for pillar in config.WATCHER_DEFAULTS:
            val = self.db.get_setting(f"watcher_{pillar}", "true")
            self.watcher_toggles[pillar] = val == "true"

    def set_ws_broadcast(self, fn):
        self._ws_broadcast_fn = fn

    def broadcast(self, event: dict):
        if self._ws_broadcast_fn:
            try:
                self._ws_broadcast_fn(event)
            except Exception as e:
                logger.warning(f"WebSocket broadcast failed: {e}")

    def on_event(self, event: dict):
        proc_name = event.get("process_name", "")
        if proc_name and proc_name.lower() in self.whitelist:
            return

        event["whitelisted"] = False
        return event

    def store_and_broadcast(self, event: dict):
        event_id = self.db.insert_alert(event)
        event["id"] = event_id
        self.broadcast(event)
        logger.info(f"Alert #{event_id}: {event.get('type')} [{event.get('severity')}]")

    def speak_event(self, event: dict):
        severity = event.get("severity", "SAFE")
        if severity == "SAFE":
            return

        etype = event.get("type", "")
        summary = event.get("summary", "")
        rec = event.get("recommendation", "")

        if severity == "CRITICAL":
            self.voice.speak_raw(f"Critical alert. {summary} {rec}")
        elif severity == "HIGH":
            self.voice.speak_raw(f"Attention. {summary} {rec}")
        elif severity in ("MEDIUM", "LOW"):
            self.voice.speak_raw(f"Heads up. {summary}")

    def start_watchers(self):
        from agent.watchers.process_watcher import ProcessWatcher
        from agent.watchers.network_watcher import NetworkWatcher
        from agent.watchers.hardware_watcher import HardwareWatcher
        from agent.watchers.filesystem_watcher import FilesystemWatcher
        from agent.watchers.idle_watcher import IdleWatcher

        watcher_classes = {
            "process": ProcessWatcher,
            "network": NetworkWatcher,
            "hardware": HardwareWatcher,
            "filesystem": FilesystemWatcher,
            "idle": IdleWatcher,
        }

        for pillar, cls in watcher_classes.items():
            if self.watcher_toggles.get(pillar, True):
                try:
                    w = cls(
                        event_callback=self.on_event,
                        db=self.db,
                        config=config,
                    )
                    self._watchers.append((pillar, w))
                    logger.info(f"Started {pillar} watcher")
                except Exception as e:
                    logger.error(f"Failed to start {pillar} watcher: {e}")

    def poll_loop(self):
        while self._running:
            for pillar, watcher in self._watchers:
                try:
                    features = watcher.poll()
                    if features:
                        self._process_pillar(pillar, watcher, features)
                except Exception as e:
                    logger.error(f"{pillar} watcher error: {e}")
            time.sleep(self.poll_interval)

    def _process_pillar(self, pillar: str, watcher, features: dict):
        from agent.detection.anomaly_engine import AnomalyEngine
        from agent.detection.rule_engine import RuleEngine
        from agent.detection.threat_classifier import classify
        from agent.explainer.xai_engine import XAIEngine

        anomaly_engine = AnomalyEngine(self.db, config)
        rule_engine = RuleEngine(config)
        xai_engine = XAIEngine(config)

        self.db.insert_telemetry(pillar, features)

        anomaly_result = anomaly_engine.update(pillar, features)
        if anomaly_result is None:
            return

        raw_events = watcher.build_events(features, anomaly_result)
        for event in raw_events:
            checked = self.on_event(event)
            if checked is None:
                continue

            rule_matches = rule_engine.match(event)
            severity = classify(anomaly_result, rule_matches)
            event["severity"] = severity

            if severity == "SAFE":
                continue

            explanation = xai_engine.explain(event, anomaly_result)
            event.update(explanation)

            self.store_and_broadcast(event)
            self.speak_event(event)

    def refresh_whitelist(self):
        self.whitelist = self.db.get_whitelist()

    def run(self):
        self._running = True
        self.voice.speak_raw("Guardian is now active. I am monitoring your system.")
        logger.info("GUARDIAN agent starting")

        self.start_watchers()

        try:
            self.poll_loop()
        except KeyboardInterrupt:
            logger.info("GUARDIAN shutting down")
        finally:
            self._running = False
            self.voice.speak_raw("Guardian is shutting down.")

    def stop(self):
        self._running = False


def start_api_server(agent):
    try:
        import uvicorn
        from agent.api.server import create_app

        app = create_app(agent)
        agent.set_ws_broadcast(app.state.ws_manager.broadcast_sync)
        uvicorn.run(app, host=config.API_HOST, port=config.API_PORT, log_level="warning")
    except Exception as e:
        logger.error(f"API server error: {e}")


def create_tray_icon(agent):
    try:
        import pystray
        from PIL import Image, ImageDraw

        def create_icon_image(color="green"):
            colors = {"green": "#22c55e", "yellow": "#eab308", "red": "#ef4444"}
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            dc = ImageDraw.Draw(img)
            c = colors.get(color, colors["green"])
            dc.ellipse([4, 4, 60, 60], fill=c, outline="white", width=2)
            dc.text((22, 18), "G", fill="white")
            return img

        def open_dashboard(icon, item):
            import webbrowser
            webbrowser.open(f"http://localhost:{config.API_PORT}")

        def toggle_mute(icon, item):
            muted = agent.voice.toggle_mute()
            item.text = "Unmute Voice" if muted else "Mute Voice"

        def exit_app(icon, item):
            agent.stop()
            icon.stop()

        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", open_dashboard),
            pystray.MenuItem("Mute Voice", toggle_mute),
            pystray.MenuItem("Exit", exit_app),
        )

        icon = pystray.Icon(
            "GUARDIAN",
            create_icon_image(),
            "GUARDIAN — Active",
            menu,
        )

        def update_icon():
            while agent._running:
                time.sleep(5)

        icon.run()
    except Exception as e:
        logger.error(f"Tray icon error: {e}")


def main():
    MODELS_DIR.mkdir(exist_ok=True)
    agent = GuardianAgent()

    api_thread = threading.Thread(target=start_api_server, args=(agent,), daemon=True)
    api_thread.start()

    agent_thread = threading.Thread(target=agent.run, daemon=True)
    agent_thread.start()

    create_tray_icon(agent)


if __name__ == "__main__":
    main()
