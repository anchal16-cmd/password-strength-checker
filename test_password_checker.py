"""
============================================================
Unit Test Suite for Password Strength Checker
============================================================
Tests all security rules, scoring mechanics, boundary conditions,
pattern heuristics, privacy protections, and backward compatibility.
Uses safe dummy test inputs only.
============================================================
"""

import io
import os
import sys
import unittest
from unittest.mock import patch

# Ensure test can find password_checker regardless of current working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from password_checker import (
    MAX_SCORE,
    check_password_strength,
    detect_common_password,
    detect_leetspeak_substitution,
    detect_repeated_characters,
    detect_sequential_patterns,
    display_results,
    prompt_password,
)


class TestPasswordChecker(unittest.TestCase):
    """Comprehensive test cases for password analysis and reporting."""

    def test_empty_input(self):
        """Verify that an empty string produces a 0 score and all failed checks."""
        analysis = check_password_strength("")
        self.assertEqual(analysis.score, 0)
        self.assertEqual(analysis.label, "WEAK")
        self.assertFalse(analysis.checks_passed["Length ≥ 8"])
        self.assertFalse(analysis.checks_passed["Uppercase letter"])
        self.assertFalse(analysis.checks_passed["Lowercase letter"])
        self.assertFalse(analysis.checks_passed["Digit (0-9)"])
        self.assertFalse(analysis.checks_passed["Special character"])
        self.assertTrue(any("at least 8" in tip for tip in analysis.tips))

    def test_very_short_passwords(self):
        """Verify that short passwords fail length and generate appropriate warnings."""
        analysis = check_password_strength("aB1!")
        self.assertFalse(analysis.checks_passed["Length ≥ 8"])
        self.assertFalse(analysis.checks_passed["Length ≥ 12 (bonus)"])
        # Passes upper, lower, digit, special (20*4 = 80)
        self.assertEqual(analysis.score, 80)
        self.assertTrue(any("Too short" in w for w in analysis.weaknesses))

    def test_long_passwords_and_passphrases(self):
        """Verify that 12+ char passwords receive the bonus and passphrases are recognized."""
        dummy_passphrase = "correct horse battery staple"
        analysis = check_password_strength(dummy_passphrase)
        self.assertTrue(analysis.checks_passed["Length ≥ 8"])
        self.assertTrue(analysis.checks_passed["Length ≥ 12 (bonus)"])
        # Should detect passphrase structure in strengths
        self.assertTrue(any("Passphrase structure" in s for s in analysis.strengths))

    def test_character_variety_detection(self):
        """Verify step-by-step point accrual for each character category."""
        # 1. Lowercase only (8 chars) -> Length (20) + Lower (20) = 40 (WEAK)
        res_lower = check_password_strength("abcdefgh")
        self.assertEqual(res_lower.score, 40)
        self.assertEqual(res_lower.label, "WEAK")

        # 2. Lowercase + Uppercase (8 chars) -> 40 + 20 = 60 (MODERATE)
        res_upper = check_password_strength("Abcdefgh")
        self.assertEqual(res_upper.score, 60)
        self.assertEqual(res_upper.label, "MODERATE")

        # 3. Lower + Upper + Digit (8 chars) -> 60 + 20 = 80 (STRONG)
        res_digit = check_password_strength("Abcdefg1")
        self.assertEqual(res_digit.score, 80)
        self.assertEqual(res_digit.label, "STRONG")

        # 4. Lower + Upper + Digit + Special (8 chars) -> 80 + 20 = 100 (VERY STRONG)
        res_all = check_password_strength("Abcdef1!")
        self.assertEqual(res_all.score, 100)
        self.assertEqual(res_all.label, "VERY STRONG")

    def test_passwords_with_spaces(self):
        """Verify that passwords with spaces are NOT stripped and spaces are preserved."""
        raw_pwd = "  SpaceTest1!  "
        analysis = check_password_strength(raw_pwd)
        self.assertEqual(len(raw_pwd), 15)
        self.assertTrue(analysis.checks_passed["Length ≥ 12 (bonus)"])

    def test_common_passwords(self):
        """Verify detection of high-risk common passwords from the offline list."""
        warning = detect_common_password("password123")
        self.assertIsNotNone(warning)
        self.assertIn("common password", warning)

        # Unrelated safe dummy password should return None
        self.assertIsNone(detect_common_password("Xy9#mK2$vL8@qP4!"))

    def test_repeated_characters(self):
        """Verify detection of 3+ consecutive repeated characters."""
        warning = detect_repeated_characters("aaaaBC123!")
        self.assertIsNotNone(warning)
        self.assertIn("repeated characters", warning)

        # Non-repeated characters should return None
        self.assertIsNone(detect_repeated_characters("abacaba123!"))

    def test_sequential_patterns(self):
        """Verify detection of sequential runs and keyboard walks."""
        # Alphabetical sequence
        self.assertIsNotNone(detect_sequential_patterns("Abcdefgh1!"))
        # Numeric sequence
        self.assertIsNotNone(detect_sequential_patterns("SafePass12345!"))
        # Keyboard walk
        self.assertIsNotNone(detect_sequential_patterns("Qwerty!2026"))

        # Random dummy password should not trigger sequential patterns
        self.assertIsNone(detect_sequential_patterns("kR7#mP9$xL2@"))

    def test_leetspeak_substitutions(self):
        """Verify detection of predictable leet substitutions for common passwords."""
        warning = detect_leetspeak_substitution("p@ssw0rd")
        self.assertIsNotNone(warning)
        self.assertIn("resembles 'password'", warning)

    def test_unicode_input(self):
        """Verify that Unicode input is processed safely without exceptions."""
        unicode_dummy = "München#2026!Café"
        analysis = check_password_strength(unicode_dummy)
        self.assertGreater(analysis.score, 0)
        self.assertTrue(analysis.checks_passed["Length ≥ 8"])

    def test_score_capping_and_boundaries(self):
        """Verify score never exceeds MAX_SCORE (100) even with full rules + bonus."""
        # 12+ chars with all 4 classes = 20*5 + 10 = 110 raw, must cap at 100
        full_dummy = "SecureExamplePass#2026"
        analysis = check_password_strength(full_dummy)
        self.assertEqual(analysis.score, MAX_SCORE)
        self.assertEqual(analysis.label, "VERY STRONG")

    def test_recommendations_match_weaknesses(self):
        """Verify that recommendations directly address detected weaknesses."""
        # Missing digits and special characters
        analysis = check_password_strength("NoDigitsOrSpecialHere")
        recs_text = " ".join(analysis.recommendations)
        self.assertTrue("numbers" in recs_text.lower() or "digit" in recs_text.lower())
        self.assertTrue("special characters" in recs_text.lower() or "symbols" in recs_text.lower())

    def test_no_actual_password_leak_in_report(self):
        """CRITICAL PRIVACY TEST: Ensure actual cleartext password never appears in report output."""
        sensitive_dummy = "SecretDummy987654!@"
        captured_output = io.StringIO()

        with patch("sys.stdout", captured_output):
            analysis = check_password_strength(sensitive_dummy)
            display_results(
                password=sensitive_dummy,
                score=analysis.score,
                label=analysis.label,
                tips=analysis.tips,
                checks_passed=analysis.checks_passed,
                analysis=analysis,
            )

        output_str = captured_output.getvalue()
        # Ensure the actual secret string is nowhere in the printed output
        self.assertNotIn(sensitive_dummy, output_str)
        # Ensure it masked it with asterisks
        self.assertIn("*" * len(sensitive_dummy), output_str)

    def test_backward_compatibility_tuple_unpacking(self):
        """Ensure existing code calling `score, label, tips, checks_passed = check_password_strength(...)` succeeds."""
        score, label, tips, checks_passed = check_password_strength("LegacyTest123!")
        self.assertIsInstance(score, int)
        self.assertIsInstance(label, str)
        self.assertIsInstance(tips, list)
        self.assertIsInstance(checks_passed, dict)

    def test_prompt_password_flow(self):
        """Test prompt choices, invalid menu options, and exit conditions."""
        with patch("sys.stdout", io.StringIO()):
            # User enters 'q' to quit
            with patch("builtins.input", return_value="q"):
                self.assertIsNone(prompt_password())

            # User chooses option 2 (visible input)
            with patch("builtins.input", side_effect=["2", "SafeDummyTest1!"]):
                self.assertEqual(prompt_password(), "SafeDummyTest1!")

            # User enters invalid choice, then quits
            with patch("builtins.input", side_effect=["invalid_choice", "99", "q"]):
                self.assertIsNone(prompt_password())


if __name__ == "__main__":
    unittest.main()
