import json
import unittest

from analyzer import CATEGORIES, MAX_CHARACTERS, RULES, analyze
from examples import EXAMPLES


class AnalyzerTests(unittest.TestCase):
    def test_empty_input(self):
        for text in ("", " \n\t"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                analyze(text)

    def test_non_text_input(self):
        for text in (None, 42, ["act now"]):
            with self.subTest(text=text), self.assertRaises(TypeError):
                analyze(text)

    def test_length_boundary(self):
        self.assertEqual(analyze("a" * MAX_CHARACTERS)["total_matches"], 0)
        with self.assertRaises(ValueError):
            analyze("a" * (MAX_CHARACTERS + 1))

    def test_action_and_deadline(self):
        result = analyze("Please verify immediately.")
        self.assertEqual(result["counts"]["urgency"], 1)
        self.assertEqual(result["findings"][0]["matched_text"], "verify immediately")

    def test_numeric_time_window(self):
        self.assertEqual(analyze("Respond within 48 hours.")["counts"]["urgency"], 1)

    def test_word_time_window(self):
        self.assertEqual(analyze("Complete this within twenty-four hours.")["counts"]["urgency"], 1)

    def test_deadline_phrase(self):
        self.assertEqual(analyze("Submit before midnight.")["counts"]["urgency"], 1)

    def test_support_role(self):
        self.assertEqual(analyze("Message from the IT department.")["counts"]["authority"], 1)

    def test_senior_role(self):
        self.assertEqual(analyze("Your manager requests a reply.")["counts"]["authority"], 1)

    def test_restriction_consequence(self):
        self.assertEqual(analyze("Your account will be permanently suspended.")["counts"]["threat"], 1)

    def test_inaction_consequence(self):
        self.assertEqual(analyze("Failure to comply could lead to further action.")["counts"]["threat"], 1)

    def test_reward_phrase(self):
        self.assertEqual(analyze("Claim your prize here.")["counts"]["reward"], 1)

    def test_curly_apostrophe(self):
        self.assertEqual(analyze("You’ve won a trip.")["counts"]["reward"], 1)

    def test_special_selection(self):
        self.assertEqual(analyze("You have been specially selected.")["counts"]["reward"], 1)

    def test_case_and_whitespace(self):
        self.assertEqual(analyze("ACT\n  IMMEDIATELY")["counts"]["urgency"], 1)

    def test_word_boundaries(self):
        self.assertEqual(analyze("A ceolike role with a free gifted book.")["total_matches"], 0)

    def test_repeated_occurrences(self):
        result = analyze("Act now. Act now.")
        self.assertEqual(result["counts"]["urgency"], 2)
        self.assertEqual(result["categories_present"], 1)

    def test_original_offsets_unicode(self):
        source = "你好🙂\nPlease ACT NOW.\nYour account is blocked."
        for finding in analyze(source)["findings"]:
            self.assertEqual(source[finding["start"]:finding["end"]], finding["matched_text"])

    def test_reading_order(self):
        result = analyze("Claim your prize. Your account is disabled. Act now.")
        self.assertEqual([f["category"] for f in result["findings"]], ["reward", "threat", "urgency"])

    def test_negation_is_context_not_silent_deletion(self):
        result = analyze("Do not act immediately.")
        self.assertEqual(result["total_matches"], 1)
        self.assertIn("negative wording", result["findings"][0]["context_note"])

    def test_educational_context(self):
        result = analyze("Training example: claim your prize.")
        self.assertIn("educational", result["findings"][0]["context_note"])

    def test_legitimate_cues_are_not_classified_as_phishing(self):
        result = analyze(EXAMPLES["04 / Legitimate urgency (synthetic)"])
        self.assertGreater(result["total_matches"], 0)
        self.assertNotIn("risk_score", result)
        self.assertNotIn("is_phishing", result)
        self.assertIn("Legitimate", result["guidance"]["urgency"]["caveat"])

    def test_no_match_does_not_mean_safe(self):
        result = analyze(EXAMPLES["06 / Subtle request - coverage gap (synthetic)"])
        self.assertEqual(result["total_matches"], 0)
        self.assertIn("No matches does not mean safe", result["limitation"])

    def test_all_four_categories(self):
        result = analyze("Your manager says act now. Your account is blocked. Claim your prize.")
        self.assertEqual(result["categories_present"], 4)
        self.assertEqual(result["counts"], dict.fromkeys(CATEGORIES, 1))

    def test_json_round_trip(self):
        result = analyze("你好🙂 Act now.")
        self.assertEqual(json.loads(json.dumps(result, ensure_ascii=False)), result)

    def test_plain_markup_is_not_executed(self):
        result = analyze('<script>alert("act now")</script>')
        self.assertEqual(result["findings"][0]["matched_text"], "act now")

    def test_context_is_bounded(self):
        source = "x" * 2000 + " act now " + "z" * 2000
        finding = analyze(source)["findings"][0]
        self.assertLessEqual(len(finding["context"]), 247)

    def test_rule_ids_unique(self):
        self.assertEqual(len(RULES), len({r.id for r in RULES}))
        self.assertTrue(all(r.category in CATEGORIES for r in RULES))

    def test_deterministic(self):
        text = EXAMPLES["01 / Account pressure (synthetic)"]
        self.assertEqual(analyze(text), analyze(text))


if __name__ == "__main__":
    unittest.main()
