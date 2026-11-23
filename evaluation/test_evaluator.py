"""Verify evaluation arithmetic independently of the analyzer's rules."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluate import metrics, validate_dataset


class EvaluationTests(unittest.TestCase):
    def test_hand_calculated_confusion_counts(self):
        rows = [
            {"expected": ["urgency", "authority"], "predicted": ["urgency", "reward"]},
            {"expected": [], "predicted": []},
        ]
        result = metrics(rows)
        # Eight message-category pairs: one TP, one FP, one FN, five TN.
        self.assertEqual({key: result["micro"][key] for key in ("tp", "fp", "fn", "tn")},
                         {"tp": 1, "fp": 1, "fn": 1, "tn": 5})
        self.assertEqual(result["micro"]["precision"], 0.5)
        self.assertEqual(result["micro"]["recall"], 0.5)
        self.assertEqual(result["micro"]["f1"], 0.5)
        self.assertEqual(result["exact_sets"], 1)

    def test_undefined_metrics_are_not_invented(self):
        result = metrics([{"expected": [], "predicted": []}])
        self.assertIsNone(result["micro"]["precision"])
        self.assertIsNone(result["micro"]["recall"])
        self.assertIsNone(result["micro"]["f1"])
        self.assertEqual(result["exact_set_agreement"], 1)

    def test_duplicate_occurrences_do_not_inflate_message_counts(self):
        result = metrics([{"expected": ["urgency"], "predicted": ["urgency", "urgency"]}])
        self.assertEqual(result["micro"]["tp"], 1)
        self.assertEqual(result["exact_sets"], 1)

    def test_all_misses_produce_zero_recall(self):
        result = metrics([{"expected": ["threat", "reward"], "predicted": []}])
        self.assertEqual(result["micro"]["fn"], 2)
        self.assertEqual(result["micro"]["recall"], 0)
        self.assertIsNone(result["micro"]["precision"])

    def test_reference_evidence_is_present_in_text(self):
        dataset = json.loads(Path(__file__).with_name("cases.json").read_text(encoding="utf-8"))
        validate_dataset(dataset)
        dataset["cases"][0]["evidence"]["urgency"] = "NOT A QUOTE FROM THIS MESSAGE"
        with self.assertRaises(ValueError):
            validate_dataset(dataset)


if __name__ == "__main__":
    unittest.main()
