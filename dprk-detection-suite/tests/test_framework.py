"""
DPRK Detection Suite — Test Framework
Validates Sigma detection rules against simulated cloud audit logs.

Usage:
    python test_framework.py

Author: Will Welch
"""

import json
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Optional

import yaml

# Add scoring module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scoring"))
from detection_scorer import DetectionScorer


def load_sigma_rules(rules_dir: str) -> List[Dict]:
    """Load all Sigma rules from YAML files, handling multi-document YAML."""
    rules = []
    rules_path = Path(rules_dir)

    if not rules_path.exists():
        print(f"[!] Rules directory not found: {rules_dir}")
        return rules

    for yml_file in sorted(rules_path.glob("*.yml")):
        with open(yml_file, "r") as f:
            content = f.read()

        # Handle multi-document YAML (multiple rules in one file)
        for doc in yaml.safe_load_all(content):
            if doc and "detection" in doc:
                doc["_source_file"] = yml_file.name
                rules.append(doc)
                print(f"  [+] Loaded: {doc.get('title', 'unnamed')} ({yml_file.name})")

    return rules


def load_logs(logs_path: str) -> List[Dict]:
    """Load simulated log events from JSON."""
    with open(logs_path, "r") as f:
        logs = json.load(f)
    print(f"  [+] Loaded {len(logs)} log events")
    return logs


def match_contains(value: str, pattern: str) -> bool:
    """Case-insensitive substring match."""
    return pattern.lower() in value.lower()


def match_endswith(value: str, pattern: str) -> bool:
    """Case-insensitive endswith match."""
    return value.lower().endswith(pattern.lower())


def evaluate_condition_block(event: Dict, condition_block: Dict) -> bool:
    """
    Evaluate a single Sigma detection condition block against a log event.
    Supports |contains, |endswith, and |contains|all modifiers.
    """
    for field_spec, expected in condition_block.items():
        # Parse field name and modifiers
        parts = field_spec.split("|")
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []

        # Map Sigma field names to our log event keys
        field_map = {
            "Image": "image",
            "ParentImage": "parent_image",
            "CommandLine": "command_line",
            "TargetFilename": "target_filename",
            "SourceProcess": "source_process",
            "DestinationHostname": "dest_hostname",
            "EventID": "event_subtype",
            "EventType": "event_type",
            "LogonType": "logon_type",
            "ModifiedField": "modified_field",
            "User": "user",
        }

        mapped_field = field_map.get(field_name, field_name.lower())
        event_value = event.get(mapped_field, "")

        # Convert to string for matching
        event_value = str(event_value)

        # Handle list of expected values (OR logic)
        if isinstance(expected, list):
            if "contains" in modifiers and "all" in modifiers:
                # All patterns must be present
                if not all(match_contains(event_value, str(p)) for p in expected):
                    return False
            elif "contains" in modifiers:
                if not any(match_contains(event_value, str(p)) for p in expected):
                    return False
            elif "endswith" in modifiers:
                if not any(match_endswith(event_value, str(p)) for p in expected):
                    return False
            else:
                if not any(str(p).lower() == event_value.lower() for p in expected):
                    return False
        else:
            # Single value
            if "contains" in modifiers:
                if not match_contains(event_value, str(expected)):
                    return False
            elif "endswith" in modifiers:
                if not match_endswith(event_value, str(expected)):
                    return False
            else:
                if str(expected).lower() != event_value.lower():
                    return False

    return True


def evaluate_rule(event: Dict, rule: Dict) -> bool:
    """
    Evaluate a Sigma rule's detection logic against a single log event.
    Parses the condition string and evaluates referenced detection blocks.
    """
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")

    if not condition:
        return False

    # Extract named detection blocks (everything except 'condition' and 'timeframe')
    blocks = {
        k: v for k, v in detection.items()
        if k not in ("condition", "timeframe") and isinstance(v, dict)
    }

    # Evaluate each named block against the event
    block_results = {}
    for block_name, block_def in blocks.items():
        block_results[block_name] = evaluate_condition_block(event, block_def)

    # Parse and evaluate condition expression
    # Support: 'and', 'or', parentheses
    return eval_condition_expr(condition, block_results)


def eval_condition_expr(condition: str, block_results: Dict[str, bool]) -> bool:
    """
    Evaluate a Sigma condition expression.
    Handles 'and', 'or', parentheses, and block references.
    """
    # Tokenize
    expr = condition.strip()

    # Replace block names with their boolean results
    # Sort by length (longest first) to avoid partial replacements
    for name in sorted(block_results.keys(), key=len, reverse=True):
        expr = expr.replace(name, str(block_results.get(name, False)))

    # Clean up for Python eval
    expr = expr.replace(" and ", " and ")
    expr = expr.replace(" or ", " or ")

    try:
        return bool(eval(expr))
    except Exception:
        return False


def run_tests():
    """Main test execution."""
    print("\n" + "=" * 80)
    print("DPRK DETECTION SUITE — TEST FRAMEWORK")
    print("=" * 80)

    base_dir = Path(__file__).parent.parent
    sigma_dir = base_dir / "rules" / "sigma"
    logs_path = Path(__file__).parent / "simulated_logs" / "sample_cloud_audit.json"

    # Load rules and logs
    print("\n[*] Loading Sigma rules...")
    rules = load_sigma_rules(str(sigma_dir))
    print(f"\n[*] Loading simulated logs...")
    logs = load_logs(str(logs_path))

    if not rules:
        print("[!] No rules loaded. Exiting.")
        return

    # Initialize scorer
    scorer = DetectionScorer()

    # Map rule titles to simplified names for scoring
    rule_name_map = {}
    for rule in rules:
        title = rule.get("title", "unnamed")
        # Create a short key from the title
        if "lateral" in title.lower():
            key = "lazarus_lateral_movement"
        elif "wallet" in title.lower() and "exfil" in title.lower():
            key = "apt38_crypto_wallet_exfil"
        elif "clipboard" in title.lower():
            key = "apt38_clipboard_monitoring"
        elif "remote access" in title.lower() or "identity anomal" in title.lower():
            key = "dprk_it_worker_indicators"
        elif "payroll" in title.lower():
            key = "dprk_it_worker_payroll"
        elif "source code" in title.lower():
            key = "dprk_it_worker_exfil"
        else:
            key = title.lower().replace(" ", "_")[:40]
        rule_name_map[title] = key
        scorer.add_rule(key)

    # Run each log event against each rule
    print(f"\n[*] Running {len(rules)} rules against {len(logs)} events...\n")

    for event in logs:
        label = event.get("label", "benign")
        expected_rule = event.get("rule_target")

        for rule in rules:
            rule_title = rule.get("title", "unnamed")
            rule_key = rule_name_map.get(rule_title, rule_title)

            matched = evaluate_rule(event, rule)

            if matched and label == "malicious" and expected_rule:
                # Check if this rule should have matched this event
                if rule_key.startswith(expected_rule) or expected_rule in rule_key:
                    scorer.record_true_positive(rule_key)
                    print(f"  [TP] {rule_key:<40} matched {event['event_id']} ✓")
                else:
                    scorer.record_false_positive(rule_key)
                    print(f"  [FP] {rule_key:<40} matched {event['event_id']} (expected: {expected_rule})")

            elif matched and label == "benign":
                scorer.record_false_positive(rule_key)
                print(f"  [FP] {rule_key:<40} matched benign {event['event_id']} ✗")

            elif matched and label == "false_positive_test":
                scorer.record_false_positive(rule_key)
                print(f"  [FP] {rule_key:<40} matched FP-test {event['event_id']} (expected)")

            elif not matched and label == "malicious" and expected_rule:
                if rule_key.startswith(expected_rule) or expected_rule in rule_key:
                    scorer.record_false_negative(rule_key)

    # Print results
    scorer.print_report()


if __name__ == "__main__":
    run_tests()
