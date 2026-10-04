import unittest

from phishing_detector import assess_url
from phishing_detector.features import analyze_url


class URLScoringTests(unittest.TestCase):
    def test_ordinary_https_url_has_lower_pattern_score(self):
        result = assess_url("https://example.com/about")
        self.assertEqual(result.level, "lower")
        self.assertEqual(result.score, 0)
        self.assertFalse(result.findings)

    def test_multiple_indicators_are_explained_and_capped(self):
        result = assess_url(
            "http://user:password@192.0.2.4:8080/a//login/verify"
        )
        self.assertEqual(result.level, "high")
        self.assertLessEqual(result.score, 100)
        self.assertGreaterEqual(len(result.findings), 5)
        self.assertEqual(
            result.score,
            min(sum(finding["points"] for finding in result.findings), 100),
        )

    def test_https_is_not_treated_as_proof_of_safety(self):
        result = assess_url("https://secure-login.example.invalid/verify")
        self.assertIn("does not mean the site is safe", result.summary)
        self.assertIn("does not prove a site is legitimate", result.as_dict()["notice"])

    def test_invalid_url_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("javascript:alert(1)")

    def test_output_contains_ordered_feature_vector(self):
        analysis = analyze_url("example.com")
        self.assertEqual(len(analysis.as_vector()), len(analysis.features))


if __name__ == "__main__":
    unittest.main()
