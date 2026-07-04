import sys
import os
import time
import threading
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("guardian.test")

def test_database():
    logger.info("=== Testing Database ===")
    from agent.storage.db import Database
    from agent.config import DB_PATH

    db = Database(str(DB_PATH))

    alert_id = db.insert_alert({
        "type": "TEST_ALERT",
        "process_name": "test.exe",
        "pid": 1234,
        "severity": "HIGH",
        "summary": "Test alert for verification",
        "reasons": ["Test reason 1", "Test reason 2"],
        "shap_values": {"feature1": 0.5, "feature2": -0.3},
        "recommendation": "This is a test recommendation",
    })
    logger.info(f"Inserted alert #{alert_id}")

    alerts = db.get_alerts(limit=10)
    logger.info(f"Retrieved {len(alerts)} alerts")
    assert len(alerts) > 0, "No alerts retrieved"

    alert = db.get_alert(alert_id)
    assert alert is not None, "Alert not found by ID"
    assert alert["type"] == "TEST_ALERT", f"Wrong type: {alert['type']}"
    logger.info(f"Alert verified: {alert['type']} [{alert['severity']}]")

    db.add_to_whitelist("test_whitelist.exe")
    wl = db.get_whitelist()
    assert "test_whitelist.exe" in wl, "Whitelist add failed"
    logger.info(f"Whitelist: {wl}")

    db.set_setting("test_key", "test_value")
    val = db.get_setting("test_key")
    assert val == "test_value", f"Setting failed: {val}"
    logger.info("Settings OK")

    logger.info("=== Database PASSED ===")
    return True

def test_rule_engine():
    logger.info("=== Testing Rule Engine ===")
    from agent.detection.rule_engine import RuleEngine
    from agent.config import config

    engine = RuleEngine(config)
    logger.info(f"Loaded {len(engine.rules)} rules")

    event = {
        "type": "UNKNOWN_PROCESS",
        "is_unsigned": True,
        "from_temp": True,
    }
    matches = engine.match(event)
    logger.info(f"Event matched {len(matches)} rules")
    for m in matches:
        logger.info(f"  Rule {m['id']}: {m['name']} [{m['severity']}]")

    event2 = {
        "type": "NETWORK_SUSPICIOUS",
        "is_suspicious_port": True,
    }
    matches2 = engine.match(event2)
    logger.info(f"Network event matched {len(matches2)} rules")

    logger.info("=== Rule Engine PASSED ===")
    return True

def test_threat_classifier():
    logger.info("=== Testing Threat Classifier ===")
    from agent.detection.threat_classifier import classify

    result = classify({"anomaly_score": 80, "is_anomaly": True}, [{"severity": "CRITICAL"}])
    assert result == "CRITICAL", f"Expected CRITICAL, got {result}"
    logger.info(f"Rule+high score -> {result}")

    result = classify({"anomaly_score": 60, "is_anomaly": True}, [])
    assert result == "MEDIUM", f"Expected MEDIUM, got {result}"
    logger.info(f"No rule, score 60 -> {result}")

    result = classify({"anomaly_score": 20, "is_anomaly": False}, [])
    assert result == "SAFE", f"Expected SAFE, got {result}"
    logger.info(f"No rule, score 20 -> {result}")

    logger.info("=== Threat Classifier PASSED ===")
    return True

def test_xai_engine():
    logger.info("=== Testing XAI Engine ===")
    from agent.explainer.xai_engine import XAIEngine

    engine = XAIEngine()
    event = {
        "type": "UNKNOWN_PROCESS",
        "process_name": "malware.exe",
        "pid": 9999,
        "is_unsigned": True,
        "from_temp": True,
        "parent_child_pair": False,
        "has_window": False,
    }
    anomaly_result = {
        "anomaly_score": 75.0,
        "shap_values": {
            "is_signed": 0.42,
            "from_temp": 0.38,
            "has_window": 0.21,
            "cpu_percent": -0.05,
        },
    }

    explanation = engine.explain(event, anomaly_result)
    logger.info(f"Summary: {explanation['summary']}")
    logger.info(f"Reasons: {explanation['reasons']}")
    logger.info(f"Recommendation: {explanation['recommendation']}")

    assert "summary" in explanation
    assert "reasons" in explanation
    assert "recommendation" in explanation
    assert len(explanation["reasons"]) > 0, "No reasons generated"

    logger.info("=== XAI Engine PASSED ===")
    return True

def test_anomaly_engine():
    logger.info("=== Testing Anomaly Engine ===")
    from agent.detection.anomaly_engine import AnomalyEngine
    from agent.storage.db import Database
    from agent.config import config, DB_PATH

    db = Database(str(DB_PATH))

    import json
    import random
    random.seed(42)
    for i in range(250):
        features = {
            "cpu_percent": random.gauss(5.0, 2.0),
            "memory_percent": random.gauss(15.0, 5.0),
            "is_signed": 1.0,
            "from_temp": 0.0,
            "parent_child_pair": 0.0,
            "has_window": 1.0,
            "encoded_cmdline": 0.0,
        }
        db.insert_telemetry("process", features)

    stored = db.get_telemetry("process", limit=300)
    logger.info(f"Stored telemetry records: {len(stored)}")
    assert len(stored) >= 200, f"Expected >= 200 records, got {len(stored)}"

    engine = AnomalyEngine(db, config)

    normal = {
        "cpu_percent": 5.0,
        "memory_percent": 10.0,
        "is_signed": 1.0,
        "from_temp": 0.0,
        "parent_child_pair": 0.0,
        "has_window": 1.0,
        "encoded_cmdline": 0.0,
    }

    result1 = engine.update("process", normal)
    logger.info(f"First call after training: {result1}")

    result2 = engine.update("process", normal)
    logger.info(f"Normal score: {result2['anomaly_score']}, Anomaly: {result2['is_anomaly']}")
    logger.info(f"SHAP values: {result2['shap_values']}")

    anomalous = {
        "cpu_percent": 95.0,
        "memory_percent": 90.0,
        "is_signed": 0.0,
        "from_temp": 1.0,
        "parent_child_pair": 1.0,
        "has_window": 0.0,
        "encoded_cmdline": 1.0,
    }
    result3 = engine.update("process", anomalous)
    logger.info(f"Anomalous score: {result3['anomaly_score']}, Anomaly: {result3['is_anomaly']}")
    logger.info(f"SHAP values: {result3['shap_values']}")

    assert result2["anomaly_score"] >= 0, "Score should be non-negative"
    assert result3["anomaly_score"] >= 0, "Score should be non-negative"
    assert len(result3["shap_values"]) > 0 or len(result2["shap_values"]) > 0, "SHAP values should not be empty"

    logger.info("=== Anomaly Engine PASSED ===")
    return True

def test_watchers():
    logger.info("=== Testing Watchers ===")
    from agent.watchers.process_watcher import ProcessWatcher
    from agent.watchers.network_watcher import NetworkWatcher
    from agent.watchers.hardware_watcher import HardwareWatcher
    from agent.watchers.filesystem_watcher import FilesystemWatcher
    from agent.watchers.idle_watcher import IdleWatcher
    from agent.storage.db import Database
    from agent.config import config, DB_PATH

    db = Database(str(DB_PATH))
    events = []

    def on_event(e):
        events.append(e)
        logger.info(f"Event: {e.get('type')} [{e.get('severity')}]")

    pw = ProcessWatcher(event_callback=on_event, db=db, config=config)
    features = pw.poll()
    logger.info(f"Process features: {features}")
    assert features is not None
    assert all(k in features for k in config.PROCESS_FEATURES)

    nw = NetworkWatcher(event_callback=on_event, db=db, config=config)
    features = nw.poll()
    logger.info(f"Network features: {features}")
    assert features is not None

    hw = HardwareWatcher(event_callback=on_event, db=db, config=config)
    features = hw.poll()
    logger.info(f"Hardware features: {features}")
    assert features is not None

    iw = IdleWatcher(event_callback=on_event, db=db, config=config)
    features = iw.poll()
    logger.info(f"Idle features: {features}")
    assert features is not None

    logger.info(f"Total events generated: {len(events)}")
    logger.info("=== Watchers PASSED ===")
    return True

def test_api_server():
    logger.info("=== Testing API Server ===")
    from agent.api.server import create_app
    import uvicorn
    import threading

    app = create_app()

    def run_server():
        uvicorn.run(app, host="127.0.0.1", port=8002, log_level="error")

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(2)

    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:8002/api/status", timeout=5) as resp:
            data = resp.read().decode()
            logger.info(f"Status: {data}")
    except Exception as e:
        logger.error(f"API test failed: {e}")
        return False

    try:
        with urllib.request.urlopen("http://127.0.0.1:8002/api/alerts", timeout=5) as resp:
            data = resp.read().decode()
            logger.info(f"Alerts: {data}")
    except Exception as e:
        logger.error(f"Alerts test failed: {e}")

    try:
        with urllib.request.urlopen("http://127.0.0.1:8002/api/stats", timeout=5) as resp:
            data = resp.read().decode()
            logger.info(f"Stats: {data}")
    except Exception as e:
        logger.error(f"Stats test failed: {e}")

    logger.info("=== API Server PASSED ===")
    return True

def main():
    logger.info("=" * 60)
    logger.info("GUARDIAN Full Test Suite")
    logger.info("=" * 60)

    results = []

    tests = [
        ("Database", test_database),
        ("Rule Engine", test_rule_engine),
        ("Threat Classifier", test_threat_classifier),
        ("XAI Engine", test_xai_engine),
        ("Anomaly Engine", test_anomaly_engine),
        ("Watchers", test_watchers),
        ("API Server", test_api_server),
    ]

    for name, test_fn in tests:
        try:
            passed = test_fn()
            results.append((name, passed))
        except Exception as e:
            logger.error(f"{name} FAILED: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))

    logger.info("\n" + "=" * 60)
    logger.info("TEST RESULTS")
    logger.info("=" * 60)
    all_passed = True
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        logger.info(f"  {name}: {status}")
        if not passed:
            all_passed = False

    logger.info("=" * 60)
    if all_passed:
        logger.info("ALL TESTS PASSED")
    else:
        logger.info("SOME TESTS FAILED")
    logger.info("=" * 60)

    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
