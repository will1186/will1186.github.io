"""
Detection Scorer — DPRK Detection Suite
Calculates true positive, false positive, false negative rates
and precision/recall per detection rule.

Author: Will Welch
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RuleScore:
    """Scoring container for a single detection rule."""
    rule_name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0


class DetectionScorer:
    """Scores detection results against labeled ground truth."""

    def __init__(self):
        self.scores: Dict[str, RuleScore] = {}

    def add_rule(self, rule_name: str):
        if rule_name not in self.scores:
            self.scores[rule_name] = RuleScore(rule_name=rule_name)

    def record_true_positive(self, rule_name: str):
        self.add_rule(rule_name)
        self.scores[rule_name].true_positives += 1

    def record_false_positive(self, rule_name: str):
        self.add_rule(rule_name)
        self.scores[rule_name].false_positives += 1

    def record_false_negative(self, rule_name: str):
        self.add_rule(rule_name)
        self.scores[rule_name].false_negatives += 1

    def get_summary(self) -> Dict:
        total_tp = sum(s.true_positives for s in self.scores.values())
        total_fp = sum(s.false_positives for s in self.scores.values())
        total_fn = sum(s.false_negatives for s in self.scores.values())

        total_detections = total_tp + total_fp
        total_actual = total_tp + total_fn

        return {
            "per_rule": {
                name: {
                    "TP": s.true_positives,
                    "FP": s.false_positives,
                    "FN": s.false_negatives,
                    "precision": round(s.precision, 4),
                    "recall": round(s.recall, 4),
                    "f1": round(s.f1, 4),
                }
                for name, s in self.scores.items()
            },
            "overall": {
                "total_TP": total_tp,
                "total_FP": total_fp,
                "total_FN": total_fn,
                "detection_rate": round(total_tp / total_actual, 4) if total_actual > 0 else 0.0,
                "false_positive_rate": round(total_fp / total_detections, 4) if total_detections > 0 else 0.0,
            },
        }

    def print_report(self):
        summary = self.get_summary()
        print("\n" + "=" * 80)
        print("DETECTION SCORING REPORT — DPRK Detection Suite")
        print("=" * 80)

        for name, metrics in summary["per_rule"].items():
            print(
                f"  Rule: {name:<40} | "
                f"TP: {metrics['TP']:<3} | "
                f"FP: {metrics['FP']:<3} | "
                f"FN: {metrics['FN']:<3} | "
                f"Precision: {metrics['precision']:.2f}  | "
                f"Recall: {metrics['recall']:.2f}  | "
                f"F1: {metrics['f1']:.2f}"
            )

        overall = summary["overall"]
        print("-" * 80)
        print(
            f"  Overall Detection Rate: {overall['detection_rate']:.1%}  |  "
            f"False Positive Rate: {overall['false_positive_rate']:.1%}"
        )
        print("=" * 80 + "\n")
