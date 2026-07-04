import json
import logging
import pickle
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("guardian.anomaly")


class AnomalyEngine:
    def __init__(self, db, config):
        self.db = db
        self.config = config
        self.models = {}
        self.explainers = {}
        self.feature_names = {
            "process": config.PROCESS_FEATURES,
            "network": config.NETWORK_FEATURES,
            "hardware": config.HARDWARE_FEATURES,
            "filesystem": config.FILESYSTEM_FEATURES,
            "idle": config.IDLE_FEATURES,
        }
        self.sample_counts = {}
        self._load_existing_models()

    def _load_existing_models(self):
        for pillar in self.feature_names:
            baseline = self.db.get_baseline(pillar)
            if baseline and baseline.get("model"):
                try:
                    model = pickle.loads(baseline["model"])
                    self.models[pillar] = model
                    self.sample_counts[pillar] = baseline.get("sample_count", 0)
                    self._init_explainer(pillar)
                    logger.info(f"Loaded existing model for {pillar}")
                except Exception as e:
                    logger.warning(f"Failed to load model for {pillar}: {e}")
                    self.sample_counts[pillar] = 0

            if pillar not in self.sample_counts:
                telemetry = self.db.get_telemetry(pillar, limit=1)
                if telemetry:
                    count_result = self.db._get_conn().execute(
                        "SELECT COUNT(*) as cnt FROM telemetry WHERE pillar = ?",
                        (pillar,)
                    ).fetchone()
                    self.sample_counts[pillar] = count_result["cnt"] if count_result else 0
                else:
                    self.sample_counts[pillar] = 0

    def _init_explainer(self, pillar: str):
        try:
            import shap
            self.explainers[pillar] = shap.TreeExplainer(self.models[pillar])
        except Exception as e:
            logger.warning(f"SHAP explainer init failed for {pillar}: {e}")
            self.explainers[pillar] = None

    def update(self, pillar: str, features: dict) -> dict:
        if pillar not in self.sample_counts:
            self.sample_counts[pillar] = 0

        self.sample_counts[pillar] += 1
        count = self.sample_counts[pillar]

        feature_names = self.feature_names.get(pillar, [])
        X = np.array([[features.get(f, 0.0) for f in feature_names]])

        if pillar not in self.models:
            if count < self.config.BASELINE_SAMPLES:
                return {
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "shap_values": {},
                    "baseline_mode": True,
                    "samples_remaining": self.config.BASELINE_SAMPLES - count,
                }
            self._train_model(pillar)

        if pillar not in self.models:
            return None

        return self._score(pillar, X, features)

    def _train_model(self, pillar: str):
        snapshots = self.db.get_telemetry(pillar, limit=self.config.BASELINE_SAMPLES)
        if len(snapshots) < 50:
            logger.warning(f"Not enough data to train {pillar} model: {len(snapshots)}")
            return

        feature_names = self.feature_names[pillar]
        X = np.array([[s.get(f, 0.0) for f in feature_names] for s in snapshots])

        model = IsolationForest(
            contamination=self.config.CONTAMINATION,
            random_state=42,
            n_estimators=100,
            max_samples="auto",
        )
        model.fit(X)

        self.models[pillar] = model
        self._init_explainer(pillar)

        model_bytes = pickle.dumps(model)
        self.db.save_baseline(pillar, model_bytes, feature_names, len(snapshots))
        logger.info(f"Trained {pillar} model with {len(snapshots)} samples")

    def _score(self, pillar: str, X: np.ndarray, features: dict) -> dict:
        model = self.models[pillar]

        raw_score = model.decision_function(X)[0]
        prediction = model.predict(X)[0]
        is_anomaly = prediction == -1

        score_normalized = max(0.0, min(100.0, (0.5 - raw_score) * 200))

        shap_dict = {}
        if pillar in self.explainers and self.explainers[pillar] is not None:
            try:
                shap_values = self.explainers[pillar].shap_values(X)
                feature_names = self.feature_names[pillar]

                if isinstance(shap_values, np.ndarray):
                    if shap_values.ndim == 2:
                        shap_vals = shap_values[0]
                    elif shap_values.ndim == 1:
                        shap_vals = shap_values
                    else:
                        shap_vals = shap_values.flatten()
                elif isinstance(shap_values, list):
                    shap_vals = np.array(shap_values[0]) if shap_values else np.zeros(len(feature_names))
                else:
                    shap_vals = np.zeros(len(feature_names))

                for i, fname in enumerate(feature_names):
                    if i < len(shap_vals):
                        val = float(shap_vals[i])
                        shap_dict[fname] = round(val, 4)
                    else:
                        shap_dict[fname] = 0.0
            except Exception as e:
                logger.debug(f"SHAP failed for {pillar}: {e}")
                feature_names = self.feature_names[pillar]
                shap_dict = {f: 0.0 for f in feature_names}

        return {
            "anomaly_score": round(score_normalized, 2),
            "is_anomaly": is_anomaly,
            "shap_values": shap_dict,
            "raw_score": round(float(raw_score), 4),
            "baseline_mode": False,
        }

    def get_model_status(self) -> dict:
        status = {}
        for pillar in self.feature_names:
            has_model = pillar in self.models
            count = self.sample_counts.get(pillar, 0)
            status[pillar] = {
                "model_trained": has_model,
                "sample_count": count,
                "baseline_needed": self.config.BASELINE_SAMPLES,
                "ready": has_model,
            }
        return status

    def set_contamination(self, value: float):
        self.config.CONTAMINATION = max(0.01, min(0.3, value))
        self.models.clear()
        self.explainers.clear()
        self.sample_counts.clear()
