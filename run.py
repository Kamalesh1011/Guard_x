import sys
import os
import time
import json
import threading
import logging
import asyncio
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.config import config, BASE_DIR, DB_PATH, MODELS_DIR
from agent.storage.db import Database
from agent.voice.speaker import JarvisVoice
from agent.detection.anomaly_engine import AnomalyEngine
from agent.detection.rule_engine import RuleEngine
from agent.detection.threat_classifier import classify
from agent.explainer.xai_engine import explain as xai_explain

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
        self._start_time = time.time()

        self.anomaly_engine = AnomalyEngine(self.db, config)
        self.rule_engine = RuleEngine(config)
        self.xai_explain = xai_explain

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
                self._ws_broadcast_fn({"type": "alert", "data": event})
            except Exception as e:
                logger.debug(f"WS broadcast failed: {e}")

    def on_event(self, event: dict) -> dict:
        proc_name = event.get("process_name", "")
        if proc_name and proc_name.lower() in self.whitelist:
            return None
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

        event_type = event.get("type", "")
        proc = event.get("process_name", "unknown")
        risk_factors = event.get("risk_factors", [])
        summary = event.get("summary", "")
        recommendation = event.get("recommendation", "")
        mitre = event.get("mitre_ttps", [])

        prefix = ""
        if severity == "CRITICAL":
            prefix = "Critical threat detected. "
        elif severity == "HIGH":
            prefix = "Security alert. "
        elif severity == "MEDIUM":
            prefix = "Warning. "
        else:
            prefix = "Notice. "

        voice_text = prefix + summary + " "

        if risk_factors:
            top_risks = sorted(risk_factors, key=lambda x: abs(x.get("contribution", 0)), reverse=True)[:3]
            for rf in top_risks:
                voice_text += rf.get("detail", "") + " "

        if mitre:
            voice_text += f"MITRE techniques detected: {', '.join(mitre[:2])}. "

        voice_text += recommendation

        voice_text = voice_text[:500]

        logger.info(f"Speaking: {voice_text[:120]}...")
        self.voice.speak_raw(voice_text)

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
                    logger.error(f"{pillar} watcher error: {e}", exc_info=True)
            time.sleep(self.poll_interval)

    def _process_pillar(self, pillar: str, watcher, features: dict):
        self.db.insert_telemetry(pillar, features)

        anomaly_result = self.anomaly_engine.update(pillar, features)
        if anomaly_result is None:
            return

        raw_events = watcher.build_events(features, anomaly_result)
        for event in raw_events:
            checked = self.on_event(event)
            if checked is None:
                continue

            rule_matches = self.rule_engine.match(event)
            severity = classify(anomaly_result, rule_matches)
            event["severity"] = severity

            if severity == "SAFE":
                continue

            explanation = self.xai_explain(event, anomaly_result)
            event.update(explanation)

            self.store_and_broadcast(event)
            self.speak_event(event)

    def refresh_whitelist(self):
        self.whitelist = self.db.get_whitelist()

    def run(self):
        self._running = True
        logger.info("GUARDIAN agent starting")
        self.start_watchers()
        self.poll_loop()

    def stop(self):
        self._running = False
        logger.info("GUARDIAN agent stopping")


def start_api_server(agent):
    import uvicorn
    from agent.api.server import create_app

    app = create_app(agent)
    agent.set_ws_broadcast(app.state.ws_manager.broadcast_sync)
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT, log_level="info")


def main():
    MODELS_DIR.mkdir(exist_ok=True)
    agent = GuardianAgent()

    api_thread = threading.Thread(target=start_api_server, args=(agent,), daemon=True)
    api_thread.start()
    logger.info(f"API server starting on {config.API_HOST}:{config.API_PORT}")

    time.sleep(2)

    agent_thread = threading.Thread(target=agent.run, daemon=True)
    agent_thread.start()
    logger.info("Watcher polling started")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
        logger.info("GUARDIAN shutdown complete")


if __name__ == "__main__":
    main()
