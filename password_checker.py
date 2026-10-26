"""
============================================================
TASK 1: Password Strength Checker
CodeOrbit Tech Cybersecurity Internship
============================================================
Description:
    Analyzes password strength against complexity rules,
    detects predictable patterns, and produces an honest,
    educational, and portfolio-ready security report.

Design Principles:
    1. Zero External Dependencies: Pure Python 3 standard library.
    2. Privacy First: Passwords are never sent over the network,
       never logged, and never displayed in cleartext in reports.
    3. Honest Evaluation: Clarifies that complexity score alone
       does not guarantee protection against data breaches or
       targeted dictionary guessing.
    4. Resilient Terminal Output: Safe ASCII formatting compatible
       with Windows PowerShell, Command Prompt, and Unix shells.
============================================================
"""

from __future__ import annotations

import getpass
import io
import re
import sys
from typing import Dict, List, NamedTuple, Optional, Tuple

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
    breakdown: List[Tuple[str, int, int, bool]]  # (Rule Name, Points Awarded, Max Points, Passed)
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
        breakdown: List[Tuple[str, int, int, bool]],
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
        return "Matches a widely known common password found in public leak lists."

    # Check if word with trailing digits/symbols stripped matches common dictionary password
    base_word = re.sub(r"[\d!@#$%^&*()-_=+\[\]{}|;:',.<>?/`~\"\\ ]+$", "", pwd_lower)
    if base_word in COMMON_PASSWORDS and len(base_word) >= 4 and base_word != pwd_lower:
        return (
            f"Built upon a widely known common word ('{base_word}') with simple trailing additions. "
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
            "Repetition lowers entropy and makes passwords easier to guess."
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
      PasswordAnalysis (NamedTuple unpacking to: score, label, tips, checks_passed)
    """
    score: int = 0
    tips: List[str] = []
    checks_passed: Dict[str, bool] = {}
    breakdown: List[Tuple[str, int, int, bool]] = []
    strengths: List[str] = []
    weaknesses: List[str] = []
    recommendations: List[str] = []

    # ----------------------------------------------------------
    # RULE 1: Minimum Length (>= 8 characters)
    # ----------------------------------------------------------
    has_len8 = len(password) >= 8
    checks_passed["Length ≥ 8"] = has_len8
    if has_len8:
        score += 20
        breakdown.append(("Length ≥ 8 characters", 20, 20, True))
        strengths.append(f"Meets the minimum length baseline ({len(password)} characters).")
    else:
        breakdown.append(("Length ≥ 8 characters", 0, 20, False))
        tips.append("Use at least 8 characters (longer = stronger).")
        weaknesses.append(f"Too short ({len(password)} characters). Short passwords can be cracked quickly.")
        recommendations.append("Increase length to at least 12–16 characters.")

    # Length Bonus (>= 12 characters)
    has_len12 = len(password) >= 12
    checks_passed["Length ≥ 12 (bonus)"] = has_len12
    if has_len12:
        score += 10
        breakdown.append(("Length ≥ 12 characters (bonus)", 10, 10, True))
        strengths.append("Contains 12 or more characters, adding substantial cryptographic search space.")
    else:
        breakdown.append(("Length ≥ 12 characters (bonus)", 0, 10, False))
        tips.append("Aim for 12+ characters for an even stronger password.")
        if has_len8:
            recommendations.append("Consider lengthening your password or using a multi-word passphrase.")

    # ----------------------------------------------------------
    # RULE 2: Uppercase Letters (A-Z)
    # ----------------------------------------------------------
    has_upper = any(char.isupper() for char in password)
    checks_passed["Uppercase letter"] = has_upper
    if has_upper:
        score += 20
        breakdown.append(("Uppercase letters (A-Z)", 20, 20, True))
        strengths.append("Includes uppercase letters, expanding the character pool.")
    else:
        breakdown.append(("Uppercase letters (A-Z)", 0, 20, False))
        tips.append("Add at least one UPPERCASE letter (e.g. A, B, C …).")
        weaknesses.append("Missing uppercase letters.")
        recommendations.append("Include uppercase letters across different positions.")

    # ----------------------------------------------------------
    # RULE 3: Lowercase Letters (a-z)
    # ----------------------------------------------------------
    has_lower = any(char.islower() for char in password)
    checks_passed["Lowercase letter"] = has_lower
    if has_lower:
        score += 20
        breakdown.append(("Lowercase letters (a-z)", 20, 20, True))
        strengths.append("Includes lowercase letters.")
    else:
        breakdown.append(("Lowercase letters (a-z)", 0, 20, False))
        tips.append("Add at least one lowercase letter (e.g. a, b, c …).")
        weaknesses.append("Missing lowercase letters.")
        recommendations.append("Include lowercase letters.")

    # ----------------------------------------------------------
    # RULE 4: Digits (0-9)
    # ----------------------------------------------------------
    has_digit = any(char.isdigit() for char in password)
    checks_passed["Digit (0-9)"] = has_digit
    if has_digit:
        score += 20
        breakdown.append(("Numbers (0-9)", 20, 20, True))
        strengths.append("Includes numerical digits.")
    else:
        breakdown.append(("Numbers (0-9)", 0, 20, False))
        tips.append("Include at least one number (0-9).")
        weaknesses.append("Missing numerical digits.")
        recommendations.append("Add numbers, ideally not at the very end as simple increments.")

    # ----------------------------------------------------------
    # RULE 5: Special Characters
    # ----------------------------------------------------------
    has_special = any(char in SPECIAL_CHARACTERS for char in password)
    checks_passed["Special character"] = has_special
    if has_special:
        score += 20
        breakdown.append(("Special characters (!@#...)", 20, 20, True))
        strengths.append("Includes special symbols, significantly increasing combinatorial complexity.")
    else:
        breakdown.append(("Special characters (!@#...)", 0, 20, False))
        tips.append("Add a special character like ! @ # $ % ^ & *")
        weaknesses.append("Missing special characters.")
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
    warnings = run_pattern_diagnostics(password)
    for warning in warnings:
        weaknesses.append(warning)
        tips.append(f"Caution: {warning}")

    # Check for passphrase structure
    if len(password) >= 14 and " " in password:
        strengths.append("Passphrase structure detected: multi-word phrases offer excellent memory retention and high entropy.")

    # General recommendations based on best practices
    if not weaknesses and not warnings:
        tips.append("Great password! No improvements needed.")
        recommendations.append("Your password meets all complexity rules. Ensure it is unique to this service.")
    else:
        recommendations.append("Use a unique password or passphrase for every account.")
        recommendations.append("Store credentials securely in a dedicated password manager.")

    return PasswordAnalysis(
        score=score,
        label=label,
        tips=tips,
        checks_passed=checks_passed,
        warnings=warnings,
        breakdown=breakdown,
        strengths=strengths,
        weaknesses=weaknesses,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# TERMINAL PRESENTATION & REPORT FORMATTING
# ---------------------------------------------------------------------------
def explain_score(score: int, label: str, has_warnings: bool) -> str:
    """Generate an honest, educational explanation of what the score represents."""
    if score >= 80:
        if has_warnings:
            return (
                "Your password meets character complexity criteria and earned a high score.\n"
                "HOWEVER, predictable patterns or common words were detected!\n"
                "In real-world attacks, dictionary tools exploit these patterns first,\n"
                "making the password vulnerable despite high variety."
            )
        return (
            "Your password meets diverse complexity criteria and adequate length.\n"
            "Remember: a high score does not guarantee immunity from data breaches\n"
            "or targeted social engineering attacks. Never reuse it across accounts."
        )
    elif score >= 60:
        return (
            "Your password has moderate strength, meeting several baseline rules.\n"
            "Adding more length or missing character types will protect it better\n"
            "against automated cracking tools."
        )
    else:
        return (
            "Your password does not meet basic modern security recommendations.\n"
            "Short or low-variety passwords can be cracked rapidly using modern\n"
            "automated cracking hardware."
        )


def display_results(
    password: str,
    score: int,
    label: str,
    tips: List[str],
    checks_passed: Dict[str, bool],
    analysis: Optional[PasswordAnalysis] = None,
) -> None:
    """
    Render a clean, well-organized, educational security report to the terminal.
    Preserves privacy: the password is NEVER displayed in cleartext.
    """
    # If extended analysis was not provided, generate it for full report fidelity
    if analysis is None:
        analysis = check_password_strength(password)

    length = len(password)
    masked_password = "*" * length

    separator = "=" * 50
    sub_separator = "-" * 50

    print("\n" + separator)
    print("               SECURITY REPORT")
    print(separator)
    print(f"Masked Input   : {masked_password} ({length} characters)")
    print(f"Strength Score : {score}/{MAX_SCORE}")
    print(f"Strength Level : {label}")
    print(sub_separator)

    # 1. SCORE CALCULATION & BREAKDOWN
    print("SCORE CALCULATION & BREAKDOWN")
    for rule_name, pts, max_pts, passed in analysis.breakdown:
        status_tag = "[PASS]" if passed else "[FAIL]"
        print(f"  {status_tag} {rule_name:<30} : +{pts:>2}/{max_pts} pts")
    print(f"  Total Score Calculated       : {score:>3}/{MAX_SCORE} (capped at {MAX_SCORE})")
    print(sub_separator)

    # 2. WHAT THIS SCORE MEANS
    print("WHAT THIS SCORE MEANS")
    print(explain_score(score, label, bool(analysis.warnings)))
    print(sub_separator)

    # 3. DETAILED SECURITY CHECKLIST
    print("SECURITY CHECKLIST")
    for rule, passed in checks_passed.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {rule}")

    pattern_status = "[WARN]" if analysis.warnings else "[PASS]"
    print(f"  {pattern_status} Common passwords & predictable patterns check")
    print(sub_separator)

    # 4. WHAT YOU DID WELL
    print("WHAT YOU DID WELL")
    if analysis.strengths:
        for item in analysis.strengths:
            print(f"  + {item}")
    else:
        print("  - No positive security criteria met yet.")
    print(sub_separator)

    # 5. WHAT NEEDS IMPROVEMENT
    print("WHAT NEEDS IMPROVEMENT")
    if analysis.weaknesses:
        for item in analysis.weaknesses:
            print(f"  - {item}")
    else:
        print("  + No immediate weaknesses detected based on checked criteria.")
    print(sub_separator)

    # 6. ACTIONABLE RECOMMENDATIONS
    print("HOW TO IMPROVE YOUR PASSWORD")
    for idx, rec in enumerate(analysis.recommendations, 1):
        print(f"  {idx}. {rec}")
    print(sub_separator)

    # 7. SECURITY REMINDER
    print("SECURITY REMINDER")
    print("  Never reuse passwords across different accounts or services.")
    print("  Use a reputable password manager and enable multi-factor")
    print("  authentication (MFA) wherever available.")
    print(separator + "\n")


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

        # Inquire if the user wishes to test another password
        next_action = input("Check another password? [Y/n]: ").strip().lower()
        if next_action in ("n", "no", "q", "quit"):
            print("\nGoodbye! Stay secure and use strong, unique passwords.\n")
            break


# ---------------------------------------------------------------------------
# ENTRY POINT GUARD
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
