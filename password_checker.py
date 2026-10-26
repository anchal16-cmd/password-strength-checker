"""
============================================================
TASK 1: Password Strength Checker
CodeOrbit Tech Cybersecurity Internship
============================================================
Description:
    Analyzes password strength against complexity rules,
    detects predictable patterns, and produces an honest,
    educational, and concise portfolio-ready security report.

Design Principles:
    1. Zero External Dependencies: Pure Python 3 standard library.
    2. Privacy First: Passwords are never sent over the network,
       never logged, and never displayed in cleartext in reports.
    3. Honest Evaluation: Scores are educational estimates, not
       guarantees of security or percentage probabilities.
    4. Clean & Concise Output: Non-repetitive, prioritized feedback.
    5. Resilient Terminal Output: Safe ASCII formatting compatible
       across all Windows, macOS, and Linux shells.
============================================================
"""

from __future__ import annotations

import getpass
import io
import re
import sys
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# TERMINAL ENCODING COMPATIBILITY
# ---------------------------------------------------------------------------
# Ensure stdout handles UTF-8 safely across Windows consoles and PowerShell.
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        elif hasattr(sys.stdout, "buffer"):
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace"
            )
    except Exception:
        pass  # Fallback gracefully to default system stream if unconfigurable


# ---------------------------------------------------------------------------
# SECURITY CONSTANTS & CONFIGURATION
# ---------------------------------------------------------------------------
MAX_SCORE: int = 100

# Recognized special characters (standard ASCII symbols)
SPECIAL_CHARACTERS: str = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\"

# Curated list of high-frequency common passwords for offline heuristic check
COMMON_PASSWORDS: set[str] = {
    "password",
    "password1",
    "password123",
    "p@ssword",
    "p@ssw0rd",
    "123456",
    "12345678",
    "123456789",
    "12345",
    "111111",
    "123123",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "administrator",
    "welcome",
    "welcome1",
    "letmein",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "sunshine",
    "princess",
    "solo",
    "starwars",
    "superman",
    "trustno1",
    "pass123",
    "login",
    "default",
}

# Common keyboard rows for walk detection
KEYBOARD_SEQUENCES: list[str] = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

# Character substitution map (common leetspeak variations)
LEET_SUBSTITUTIONS = str.maketrans(
    {
        "@": "a",
        "4": "a",
        "3": "e",
        "1": "i",
        "!": "i",
        "0": "o",
        "$": "s",
        "5": "s",
        "7": "t",
        "+": "t",
        "8": "b",
    }
)


# ---------------------------------------------------------------------------
# STRUCTURED DATA MODEL
# ---------------------------------------------------------------------------
class PasswordAnalysis(tuple):
    """
    A 4-element tuple (score, label, tips, checks_passed) providing 100%
    backward compatibility with legacy code unpacking:
        `score, label, tips, checks_passed = check_password_strength(...)`
    while attaching extended diagnostic attributes for modern reporting.
    """

    score: int
    label: str
    tips: List[str]
    checks_passed: Dict[str, bool]
    warnings: List[str]
    breakdown: List[Tuple[str, int, int, str]]  # (Rule Name, Points Awarded, Max Points, Status)
    strengths: List[str]
    weaknesses: List[str]
    recommendations: List[str]

    def __new__(
        cls,
        score: int,
        label: str,
        tips: List[str],
        checks_passed: Dict[str, bool],
        warnings: List[str],
        breakdown: List[Tuple[str, int, int, str]],
        strengths: List[str],
        weaknesses: List[str],
        recommendations: List[str],
    ):
        # Base tuple contains only the 4 legacy elements
        instance = super().__new__(cls, (score, label, tips, checks_passed))
        instance.score = score
        instance.label = label
        instance.tips = tips
        instance.checks_passed = checks_passed
        instance.warnings = warnings
        instance.breakdown = breakdown
        instance.strengths = strengths
        instance.weaknesses = weaknesses
        instance.recommendations = recommendations
        return instance


# ---------------------------------------------------------------------------
# PATTERN & HEURISTIC DETECTION HELPERS
# ---------------------------------------------------------------------------
def detect_common_password(password: str) -> Optional[str]:
    """Check if the password matches or is built directly upon a widely known common password."""
    pwd_lower = password.lower()
    if pwd_lower in COMMON_PASSWORDS:
        return "Matches a widely known common password found in public breach lists."

    # Check if word with trailing digits/symbols stripped matches common dictionary password
    base_word = re.sub(r"[\d!@#$%^&*()-_=+\[\]{}|;:',.<>?/`~\"\\ ]+$", "", pwd_lower)
    if base_word in COMMON_PASSWORDS and len(base_word) >= 4 and base_word != pwd_lower:
        return (
            f"Built upon a widely known common word ('{base_word}') with trailing characters. "
            "Dictionary attacks prioritize base words with appended years or symbols."
        )
    return None


def detect_leetspeak_substitution(password: str) -> Optional[str]:
    """Detect if predictable character substitutions are masking a common word."""
    pwd_lower = password.lower()
    de_leet = pwd_lower.translate(LEET_SUBSTITUTIONS)
    base_de_leet = re.sub(r"[\d!@#$%^&*()-_=+\[\]{}|;:',.<>?/`~\"\\ ]+$", "", de_leet)

    for common in COMMON_PASSWORDS:
        if len(common) >= 4:
            if common in (de_leet, base_de_leet) or (len(common) >= 5 and common in de_leet):
                if common != pwd_lower:
                    return (
                        f"Predictable character substitution detected (resembles '{common}'). "
                        "Cracking tools easily reverse substitutions like @->a, 0->o, or $->s."
                    )
    return None


def detect_repeated_characters(password: str) -> Optional[str]:
    """Detect 3 or more consecutive identical characters (e.g., 'aaa' or '1111')."""
    if re.search(r"(.)\1{2,}", password):
        return (
            "Contains 3 or more consecutive repeated characters. "
            "Repetition significantly lowers entropy and simplifies guessing."
        )
    return None


def detect_sequential_patterns(password: str) -> Optional[str]:
    """
    Detect consecutive alphabetical, numerical, or keyboard sequences of 3+ characters.
    Examples: 'abc', '123', 'cba', '321', 'qwer'.
    """
    pwd_lower = password.lower()
    length = len(pwd_lower)

    # 1. Alphabetical and numeric sequences (ascending & descending)
    for i in range(length - 2):
        chunk = pwd_lower[i : i + 3]
        if chunk.isalnum():
            # Check ASCII character continuity
            c0, c1, c2 = ord(chunk[0]), ord(chunk[1]), ord(chunk[2])
            if (c1 == c0 + 1 and c2 == c1 + 1) or (c1 == c0 - 1 and c2 == c1 - 1):
                return (
                    f"Contains simple sequential pattern ('{chunk}'). "
                    "Sequential runs are prioritized in dictionary and brute-force attacks."
                )

    # 2. Keyboard sequences
    for row in KEYBOARD_SEQUENCES:
        for i in range(len(row) - 2):
            key_chunk = row[i : i + 3]
            if key_chunk in pwd_lower or key_chunk[::-1] in pwd_lower:
                return (
                    f"Contains predictable keyboard walk ('{key_chunk}'). "
                    "Keyboard patterns are among the first tested by cracking software."
                )

    return None


def run_pattern_diagnostics(password: str) -> List[str]:
    """Aggregate all pattern and heuristic warnings for a given password."""
    warnings: List[str] = []

    for detector in (
        detect_common_password,
        detect_leetspeak_substitution,
        detect_repeated_characters,
        detect_sequential_patterns,
    ):
        result = detector(password)
        if result:
            warnings.append(result)

    return warnings


# ---------------------------------------------------------------------------
# CORE STRENGTH CHECKER FUNCTION
# ---------------------------------------------------------------------------
def check_password_strength(password: str) -> PasswordAnalysis:
    """
    Analyze password strength according to the preserved 5-rule criteria
    and bonus structure, supplemented with pattern heuristics.

    Preserved Scoring Model:
      - Rule 1: Length >= 8           (+20 pts)
      - Bonus:  Length >= 12 (bonus)  (+10 pts)
      - Rule 2: Uppercase letter      (+20 pts)
      - Rule 3: Lowercase letter      (+20 pts)
      - Rule 4: Digit (0-9)           (+20 pts)
      - Rule 5: Special character     (+20 pts)
      Total raw points = up to 110, capped at 100 via min(score, 100).

    Categories:
      - <= 40  : WEAK
      - 41-60  : MODERATE
      - 61-80  : STRONG
      - 81-100 : VERY STRONG

    Returns:
      PasswordAnalysis (NamedTuple-like tuple unpacking to: score, label, tips, checks_passed)
    """
    score: int = 0
    tips: List[str] = []
    checks_passed: Dict[str, bool] = {}
    breakdown: List[Tuple[str, int, int, str]] = []
    strengths: List[str] = []
    weaknesses: List[str] = []
    recommendations: List[str] = []

    # Handle unperformed check scenario (empty input)
    is_empty = len(password) == 0

    # ----------------------------------------------------------
    # RULE 1: Minimum Length (>= 8 characters)
    # ----------------------------------------------------------
    if is_empty:
        has_len8 = False
        checks_passed["Length ≥ 8"] = False
        breakdown.append(("Length ≥ 8 characters", 0, 20, "FAIL"))
        tips.append("Use at least 8 characters (longer = stronger).")
        weaknesses.append("Password is empty. A valid password is required.")
        recommendations.append("Enter a password with at least 12–16 characters.")
    else:
        has_len8 = len(password) >= 8
        checks_passed["Length ≥ 8"] = has_len8
        if has_len8:
            score += 20
            breakdown.append(("Length ≥ 8 characters", 20, 20, "PASS"))
            strengths.append(f"Meets minimum length requirement ({len(password)} characters).")
        else:
            breakdown.append(("Length ≥ 8 characters", 0, 20, "FAIL"))
            tips.append("Use at least 8 characters (longer = stronger).")
            weaknesses.append(f"Too short ({len(password)} characters). Short passwords are cracked quickly.")
            recommendations.append("Increase length to at least 12–16 characters.")

    # Length Bonus (>= 12 characters)
    if is_empty:
        has_len12 = False
        checks_passed["Length ≥ 12 (bonus)"] = False
        breakdown.append(("Length ≥ 12 characters (bonus)", 0, 10, "FAIL"))
    else:
        has_len12 = len(password) >= 12
        checks_passed["Length ≥ 12 (bonus)"] = has_len12
        if has_len12:
            score += 10
            breakdown.append(("Length ≥ 12 characters (bonus)", 10, 10, "PASS"))
            strengths.append("Contains 12 or more characters for substantial cryptographic search space.")
        else:
            breakdown.append(("Length ≥ 12 characters (bonus)", 0, 10, "FAIL"))
            tips.append("Aim for 12+ characters for an even stronger password.")
            if has_len8:
                recommendations.append("Lengthen your password or use a multi-word passphrase.")

    # ----------------------------------------------------------
    # RULE 2: Uppercase Letters (A-Z)
    # ----------------------------------------------------------
    if is_empty:
        checks_passed["Uppercase letter"] = False
        breakdown.append(("Uppercase letters (A-Z)", 0, 20, "FAIL"))
        tips.append("Add at least one UPPERCASE letter (e.g. A, B, C …).")
        weaknesses.append("Missing uppercase letters (A-Z).")
    else:
        has_upper = any(char.isupper() for char in password)
        checks_passed["Uppercase letter"] = has_upper
        if has_upper:
            score += 20
            breakdown.append(("Uppercase letters (A-Z)", 20, 20, "PASS"))
            strengths.append("Includes uppercase letters (A-Z).")
        else:
            breakdown.append(("Uppercase letters (A-Z)", 0, 20, "FAIL"))
            tips.append("Add at least one UPPERCASE letter (e.g. A, B, C …).")
            weaknesses.append("Missing uppercase letters (A-Z).")
            recommendations.append("Add uppercase letters across different positions.")

    # ----------------------------------------------------------
    # RULE 3: Lowercase Letters (a-z)
    # ----------------------------------------------------------
    if is_empty:
        checks_passed["Lowercase letter"] = False
        breakdown.append(("Lowercase letters (a-z)", 0, 20, "FAIL"))
        tips.append("Add at least one lowercase letter (e.g. a, b, c …).")
        weaknesses.append("Missing lowercase letters (a-z).")
    else:
        has_lower = any(char.islower() for char in password)
        checks_passed["Lowercase letter"] = has_lower
        if has_lower:
            score += 20
            breakdown.append(("Lowercase letters (a-z)", 20, 20, "PASS"))
            strengths.append("Includes lowercase letters (a-z).")
        else:
            breakdown.append(("Lowercase letters (a-z)", 0, 20, "FAIL"))
            tips.append("Add at least one lowercase letter (e.g. a, b, c …).")
            weaknesses.append("Missing lowercase letters (a-z).")
            recommendations.append("Include lowercase letters.")

    # ----------------------------------------------------------
    # RULE 4: Digits (0-9)
    # ----------------------------------------------------------
    if is_empty:
        checks_passed["Digit (0-9)"] = False
        breakdown.append(("Numbers (0-9)", 0, 20, "FAIL"))
        tips.append("Include at least one number (0-9).")
        weaknesses.append("Missing numerical digits (0-9).")
    else:
        has_digit = any(char.isdigit() for char in password)
        checks_passed["Digit (0-9)"] = has_digit
        if has_digit:
            score += 20
            breakdown.append(("Numbers (0-9)", 20, 20, "PASS"))
            strengths.append("Includes numerical digits (0-9).")
        else:
            breakdown.append(("Numbers (0-9)", 0, 20, "FAIL"))
            tips.append("Include at least one number (0-9).")
            weaknesses.append("Missing numerical digits (0-9).")
            recommendations.append("Add numbers, avoiding simple increments at the very end.")

    # ----------------------------------------------------------
    # RULE 5: Special Characters
    # ----------------------------------------------------------
    if is_empty:
        checks_passed["Special character"] = False
        breakdown.append(("Special characters (!@#...)", 0, 20, "FAIL"))
        tips.append("Add a special character like ! @ # $ % ^ & *")
        weaknesses.append("Missing special characters (!@#$%...).")
    else:
        has_special = any(char in SPECIAL_CHARACTERS for char in password)
        checks_passed["Special character"] = has_special
        if has_special:
            score += 20
            breakdown.append(("Special characters (!@#...)", 20, 20, "PASS"))
            strengths.append("Includes special characters (!@#$...).")
        else:
            breakdown.append(("Special characters (!@#...)", 0, 20, "FAIL"))
            tips.append("Add a special character like ! @ # $ % ^ & *")
            weaknesses.append("Missing special characters (!@#$%...).")
            recommendations.append("Include special characters (symbols, punctuation).")

    # ----------------------------------------------------------
    # SCORE CAPPING & CATEGORIZATION
    # ----------------------------------------------------------
    score = min(score, MAX_SCORE)

    if score <= 40:
        label = "WEAK"
    elif score <= 60:
        label = "MODERATE"
    elif score <= 80:
        label = "STRONG"
    else:
        label = "VERY STRONG"

    # ----------------------------------------------------------
    # PATTERN HEURISTICS (DIAGNOSTICS & WARNINGS)
    # ----------------------------------------------------------
    if not is_empty:
        warnings = run_pattern_diagnostics(password)
        for warning in warnings:
            weaknesses.append(warning)
            tips.append(f"Caution: {warning}")

        if warnings:
            recommendations.append("Avoid common words, sequential runs, and predictable substitutions.")

        # Check for passphrase structure
        if len(password) >= 14 and " " in password:
            strengths.append("Passphrase structure detected: multi-word phrases offer excellent entropy and recall.")
    else:
        warnings = []

    # Final recommendations consolidation
    if not weaknesses and not warnings:
        tips.append("Great password! No improvements needed.")
        recommendations.append("Password meets complexity criteria. Ensure it is unique to this account.")
        recommendations.append("Store credentials securely in a dedicated password manager.")
        recommendations.append("Enable multi-factor authentication (MFA) wherever available.")
    else:
        # Prioritize and ensure password manager & uniqueness are available
        recommendations.append("Use a unique password or passphrase for every account.")
        recommendations.append("Store credentials securely in a dedicated password manager.")

    # Deduplicate recommendations preserving order
    seen_recs = set()
    deduped_recs = []
    for r in recommendations:
        if r not in seen_recs:
            seen_recs.add(r)
            deduped_recs.append(r)

    # Deduplicate weaknesses preserving order
    seen_weak = set()
    deduped_weaknesses = []
    for w in weaknesses:
        if w not in seen_weak:
            seen_weak.add(w)
            deduped_weaknesses.append(w)

    return PasswordAnalysis(
        score=score,
        label=label,
        tips=tips,
        checks_passed=checks_passed,
        warnings=warnings,
        breakdown=breakdown,
        strengths=strengths,
        weaknesses=deduped_weaknesses,
        recommendations=deduped_recs,
    )


# ---------------------------------------------------------------------------
# TERMINAL PRESENTATION & REPORT FORMATTING
# ---------------------------------------------------------------------------
def display_results(
    password: str,
    score: int,
    label: str,
    tips: List[str],
    checks_passed: Dict[str, bool],
    analysis: Optional[PasswordAnalysis] = None,
) -> None:
    """
    Render a clean, concise, educational security report to the terminal.
    Follows the streamlined design requested:
      - Title banner
      - Strength score & level
      - Masked input & length
      - WHAT IS GOOD? (only detected strengths)
      - WHAT NEEDS IMPROVEMENT? (only detected weaknesses)
      - HOW TO IMPROVE? (maximum 3 actionable recommendations)
      - SECURITY TIP
    """
    if analysis is None:
        analysis = check_password_strength(password)

    length = len(password)
    masked_password = "*" * length

    separator = "=" * 50
    sub_separator = "-" * 50

    print("\n" + separator)
    print("           PASSWORD STRENGTH CHECKER")
    print(separator)
    print("\n" + "--------------- SECURITY REPORT -----------------")
    print(f"\nStrength Score : {score}/{MAX_SCORE}")
    print(f"Strength Level : {label}")
    print(f"Masked Input   : {masked_password} ({length} characters)")

    # 1. WHAT IS GOOD?
    print("\nWHAT IS GOOD?")
    if analysis.strengths:
        for item in analysis.strengths:
            print(f"  + {item}")
    else:
        print("  + None detected yet.")

    # 2. WHAT NEEDS IMPROVEMENT?
    print("\nWHAT NEEDS IMPROVEMENT?")
    if analysis.weaknesses:
        for item in analysis.weaknesses:
            print(f"  - {item}")
    else:
        print("  + No weaknesses detected based on checked criteria.")

    # 3. HOW TO IMPROVE? (Show top 3 actionable recommendations only)
    print("\nHOW TO IMPROVE?")
    top_recommendations = analysis.recommendations[:3]
    for idx, rec in enumerate(top_recommendations, 1):
        print(f"  {idx}. {rec}")

    # 4. SECURITY TIP
    print("\nSECURITY TIP")
    print("Use a long, unique password. Store it in a password manager")
    print("and enable MFA wherever possible.")
    print("\n" + separator)


def display_detailed_breakdown(analysis: PasswordAnalysis) -> None:
    """
    Optional detailed report feature: displays full score breakdown and checklist.
    Highlights PASS, FAIL, or NOT CHECKED status honestly.
    """
    sub_sep = "-" * 50
    print("\n" + sub_sep)
    print("         DETAILED SCORE BREAKDOWN")
    print(sub_sep)
    print("CRITERIA POINTS:")
    for rule_name, pts, max_pts, status in analysis.breakdown:
        print(f"  [{status:<4}] {rule_name:<30} : +{pts:>2}/{max_pts} pts")
    print(f"  Total Score Calculated       : {analysis.score:>3}/{MAX_SCORE} (capped at {MAX_SCORE})")
    print("\nEDUCATIONAL NOTE:")
    print("  The score is an educational estimate of complexity, not a guarantee")
    print("  of security or a percentage probability of being breached.")

    print("\nDETAILED CHECKLIST:")
    for rule, passed in analysis.checks_passed.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status:<4}] {rule}")

    pattern_status = "FAIL" if analysis.warnings else "PASS"
    print(f"  [{pattern_status:<4}] Common passwords & predictable patterns check")
    print(sub_sep + "\n")


# ---------------------------------------------------------------------------
# SAFE USER INPUT & INTERACTION
# ---------------------------------------------------------------------------
def prompt_password() -> Optional[str]:
    """
    Safely request a test password from the user.
    Uses hidden input via getpass when supported, falling back gracefully
    to visible input in unsupported environments.

    Returns:
        The raw password entered by the user, or None if the user requested exit.
    """
    print("\nHow would you like to enter your test password?")
    print("  [1] Hidden input (recommended - characters will not be shown)")
    print("  [2] Visible input (standard typing)")
    print("  [q] Quit")

    while True:
        choice = input("Select an option (1, 2, or q): ").strip().lower()

        if choice in ("q", "quit", "exit"):
            return None

        if choice == "1":
            try:
                # getpass hides typed input to prevent shoulder-surfing
                pwd = getpass.getpass("Enter a test password (hidden): ")
                return pwd
            except (io.UnsupportedOperation, OSError, EOFError):
                print("[!] Hidden input not supported in this terminal session. Using standard input.")
                return input("Enter a test password: ")

        elif choice == "2":
            return input("Enter a test password: ")

        else:
            print("Invalid choice. Please enter 1, 2, or q.")


# ---------------------------------------------------------------------------
# MAIN APPLICATION LOOP
# ---------------------------------------------------------------------------
def main() -> None:
    """
    Main interactive entry point loop for the Password Strength Checker.
    """
    print("\n" + "=" * 50)
    print("           PASSWORD STRENGTH CHECKER")
    print("==================================================")
    print("Analyze your password and learn how to improve it.")
    print("Offline evaluation only - your password is never")
    print("stored, logged, or transmitted anywhere.")
    print("=" * 50)

    while True:
        password = prompt_password()

        # Handle exit request
        if password is None:
            print("\nGoodbye! Stay secure and use strong, unique passwords.\n")
            break

        # Check for empty input (whitespace-only or zero characters)
        if len(password) == 0:
            print("\n[!] Input was empty. Please enter a valid test password.\n")
            continue

        # Allow user to type quit directly if entered in visible prompt
        if password.lower() in ("quit", "exit"):
            print("\nGoodbye! Stay secure and use strong, unique passwords.\n")
            break

        # Perform analysis and present results
        analysis = check_password_strength(password)
        display_results(
            password=password,
            score=analysis.score,
            label=analysis.label,
            tips=analysis.tips,
            checks_passed=analysis.checks_passed,
            analysis=analysis,
        )

        # Inquire if user wants another password or detailed breakdown
        while True:
            next_action = input("\nCheck another password? [Y/n] (or 'd' for detailed breakdown): ").strip().lower()
            if next_action in ("d", "details", "detailed"):
                display_detailed_breakdown(analysis)
                continue
            break

        if next_action in ("n", "no", "q", "quit"):
            print("\nGoodbye! Stay secure and use strong, unique passwords.\n")
            break


# ---------------------------------------------------------------------------
# ENTRY POINT GUARD
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
