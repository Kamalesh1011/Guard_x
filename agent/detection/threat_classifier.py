def classify(anomaly_result: dict, rule_matches: list) -> str:
    has_rule = len(rule_matches) > 0
    score = anomaly_result.get("anomaly_score", 0)
    is_anomaly = anomaly_result.get("is_anomaly", False)

    if has_rule:
        for rule in rule_matches:
            rule_severity = rule.get("severity", "MEDIUM").upper()
            if rule_severity == "CRITICAL":
                return "CRITICAL"

    if has_rule and score > 70:
        return "CRITICAL"
    elif has_rule or (is_anomaly and score > 70):
        return "HIGH"
    elif score > 50:
        return "MEDIUM"
    elif score > 30:
        return "LOW"
    else:
        return "SAFE"
