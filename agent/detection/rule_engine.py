import json
import logging
from pathlib import Path

logger = logging.getLogger("guardian.rules")


class RuleEngine:
    def __init__(self, config):
        self.config = config
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        rules_path = Path(self.config.RULES_PATH) if hasattr(self.config, "RULES_PATH") else None
        if rules_path is None:
            from agent.config import RULES_PATH
            rules_path = RULES_PATH

        if rules_path.exists():
            try:
                data = json.loads(rules_path.read_text(encoding="utf-8"))
                self.rules = data.get("rules", [])
                logger.info(f"Loaded {len(self.rules)} detection rules")
            except Exception as e:
                logger.error(f"Failed to load rules: {e}")
                self.rules = []
        else:
            logger.warning(f"Rules file not found: {rules_path}")
            self.rules = []

    def match(self, event: dict) -> list:
        matches = []
        event_type = event.get("type", "")

        for rule in self.rules:
            if rule.get("event_type") and rule["event_type"] != event_type:
                continue

            condition = rule.get("condition", {})
            if self._evaluate_condition(condition, event):
                matches.append(rule)

        return matches

    def _evaluate_condition(self, condition: dict, event: dict) -> bool:
        for key, expected in condition.items():
            actual = event.get(key)

            if isinstance(expected, bool):
                if bool(actual) != expected:
                    return False
            elif isinstance(expected, (int, float)):
                if isinstance(actual, (int, float)):
                    if key in ("events_per_3s", "unknown_proc_count", "cpu_vs_baseline"):
                        if actual < expected:
                            return False
                    else:
                        if actual != expected:
                            return False
                else:
                    return False
            elif isinstance(expected, str):
                if str(actual).lower() != expected.lower():
                    return False
            else:
                if actual != expected:
                    return False

        return True

    def add_rule(self, rule: dict):
        if "id" not in rule:
            rule["id"] = f"R{len(self.rules) + 1:03d}"
        self.rules.append(rule)

    def remove_rule(self, rule_id: str):
        self.rules = [r for r in self.rules if r.get("id") != rule_id]

    def get_rules(self) -> list:
        return self.rules

    def save_rules(self):
        from agent.config import RULES_PATH
        data = {"rules": self.rules}
        Path(RULES_PATH).write_text(json.dumps(data, indent=2), encoding="utf-8")
