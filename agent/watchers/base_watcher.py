from abc import ABC, abstractmethod
from datetime import datetime


class BaseWatcher(ABC):
    def __init__(self, event_callback, db, config):
        self.event_cb = event_callback
        self.db = db
        self.config = config
        self.name = self.__class__.__name__

    @abstractmethod
    def poll(self) -> dict:
        pass

    @abstractmethod
    def build_events(self, features: dict, anomaly_result: dict) -> list:
        pass

    def emit(self, event: dict) -> dict:
        event["watcher"] = self.name
        event["timestamp"] = datetime.utcnow().isoformat()
        return event

    def store_snapshot(self, features: dict):
        self.db.insert_telemetry(self.name.lower(), features)
