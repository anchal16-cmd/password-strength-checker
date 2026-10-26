# ============================================================
# TASK 1: Password Strength Checker
# CodeOrbit Tech Cybersecurity Internship
# ============================================================
# What it does:
#   Checks a password against 5 security rules and gives it
#   a strength score (0-100). Shows friendly tips to improve.
# How to run:
#   python password_checker.py
# No external libraries needed — only built-in Python.
# ============================================================


import sys
import io

# Fix for Windows terminals that don't support emoji by default.
# This makes the coloured labels and tick marks display correctly.
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


def check_password_strength(password):
    """
    Analyse a password and return:
      - score        : int  (0 – 100)
      - label        : str  ("Weak" / "Moderate" / "Strong" / "Very Strong")
      - tips         : list of improvement suggestions
      - checks_passed: dict showing which rules passed / failed
    """

    # ----------------------------------------------------------
    # STEP 1: Define the five security rules we will check.
    # Each rule is worth 20 points → max score = 100.
    # ----------------------------------------------------------
    score        = 0          # running total (starts at zero)
    tips         = []         # list of advice strings
    checks_passed = {}        # dictionary: rule name → True/False

    # ----------------------------------------------------------
    # RULE 1 — Minimum length (at least 8 characters)
    # Short passwords are cracked in seconds by brute-force.
    # ----------------------------------------------------------
    if len(password) >= 8:
        score += 20
        checks_passed["Length ≥ 8"] = True
    else:
        checks_passed["Length ≥ 8"] = False
        tips.append("❌  Use at least 8 characters (longer = stronger).")

    # Bonus: extra 10 pts if password is 12+ characters long
    if len(password) >= 12:
        score += 10
        checks_passed["Length ≥ 12 (bonus)"] = True
    else:
        checks_passed["Length ≥ 12 (bonus)"] = False
        tips.append("💡  Aim for 12+ characters for an even stronger password.")

    # ----------------------------------------------------------
    # RULE 2 — Uppercase letters (A-Z)
    # Mixing cases increases the number of possible combinations.
    # We use the built-in any() function with str.isupper().
    # ----------------------------------------------------------
    if any(char.isupper() for char in password):
        score += 20
        checks_passed["Uppercase letter"] = True
    else:
        checks_passed["Uppercase letter"] = False
        tips.append("❌  Add at least one UPPERCASE letter (e.g. A, B, C …).")

    # ----------------------------------------------------------
    # RULE 3 — Lowercase letters (a-z)
    # ----------------------------------------------------------
    if any(char.islower() for char in password):
        score += 20
        checks_passed["Lowercase letter"] = True
    else:
        checks_passed["Lowercase letter"] = False
        tips.append("❌  Add at least one lowercase letter (e.g. a, b, c …).")

    # ----------------------------------------------------------
    # RULE 4 — Digits (0-9)
    # ----------------------------------------------------------
    if any(char.isdigit() for char in password):
        score += 20
        checks_passed["Digit (0-9)"] = True
    else:
        checks_passed["Digit (0-9)"] = False
        tips.append("❌  Include at least one number (0-9).")

    # ----------------------------------------------------------
    # RULE 5 — Special characters (!@#$%^&* etc.)
    # We define a string of common special characters and check
    # if any character in the password is found inside it.
    # ----------------------------------------------------------
    special_chars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\"

    if any(char in special_chars for char in password):
        score += 20
        checks_passed["Special character"] = True
    else:
        checks_passed["Special character"] = False
        tips.append("❌  Add a special character like ! @ # $ % ^ & *")

    # ----------------------------------------------------------
    # STEP 2: Cap the score at 100 and assign a strength label.
    # ----------------------------------------------------------
    score = min(score, 100)   # cap at 100 (bonus could push past)

    if score <= 40:
        label = "🔴  WEAK"
    elif score <= 60:
        label = "🟠  MODERATE"
    elif score <= 80:
        label = "🟡  STRONG"
    else:
        label = "🟢  VERY STRONG"

    # If no tips, the password is perfect
    if not tips:
        tips.append("✅  Great password! No improvements needed.")

    return score, label, tips, checks_passed


def display_results(password, score, label, tips, checks_passed):
    """
    Pretty-print the analysis results to the terminal.
    """
    print("\n" + "=" * 50)
    print("       PASSWORD STRENGTH REPORT")
    print("=" * 50)

    # Show the password (masked after first 2 chars for privacy)
    masked = password[:2] + "*" * (len(password) - 2)
    print(f"  Password   : {masked}")
    print(f"  Length     : {len(password)} characters")
    print(f"  Score      : {score}/100")
    print(f"  Strength   : {label}")

    print("\n  --- Security Checks ---")
    for rule, passed in checks_passed.items():
        status = "✅" if passed else "❌"
        print(f"  {status}  {rule}")

    print("\n  --- Improvement Tips ---")
    for tip in tips:
        print(f"  {tip}")

    print("=" * 50 + "\n")


def main():
    """
    Main loop — keeps asking for passwords until the user quits.
    """
    print("\n🔐  PASSWORD STRENGTH CHECKER")
    print("    CodeOrbit Tech Cybersecurity Internship")
    print("    Type 'quit' to exit.\n")

    while True:
        # Get password input from the user
        password = input("Enter a password to check: ").strip()

        # Allow the user to exit gracefully
        if password.lower() == "quit":
            print("\n👋  Goodbye! Stay secure!\n")
            break

        # Handle empty input
        if not password:
            print("⚠️   Please enter a password (it cannot be empty).\n")
            continue

        # Run the strength check
        score, label, tips, checks_passed = check_password_strength(password)

        # Display results
        display_results(password, score, label, tips, checks_passed)


# Standard Python entry-point guard
# This ensures main() only runs when the script is executed directly,
# not when it is imported as a module.
if __name__ == "__main__":
    main()