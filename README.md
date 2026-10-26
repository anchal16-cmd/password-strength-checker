# Password Strength Checker & Security Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-brightgreen.svg)]()
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Offline-orange.svg)]()

An educational, portfolio-ready cybersecurity tool designed to evaluate password complexity, detect predictable patterns, and provide actionable security recommendations through a clean, beginner-friendly terminal interface. Built strictly with Python 3's standard library with zero external dependencies.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Educational Learning Outcomes](#educational-learning-outcomes)
- [Features](#features)
- [System Requirements](#system-requirements)
- [How to Run](#how-to-run)
- [How the Scoring System Works](#how-the-scoring-system-works)
- [Sample Terminal Run](#sample-terminal-run)
- [What the Score Can and Cannot Tell You](#what-the-score-can-and-cannot-tell-you)
- [Privacy and Security Principles](#privacy-and-security-principles)
- [Running Automated Tests](#running-automated-tests)

---

## Project Overview

In real-world cybersecurity, many users believe that substituting letters with symbols (such as replacing `a` with `@` or `o` with `0`) makes their password uncrackable. In reality, modern password-cracking software (like Hashcat and John the Ripper) uses rule-based attacks that instantly reverse these predictable patterns.

This project delivers:
1. **Traditional Complexity Scoring**: Evaluates length, case mixing, numbers, and special symbols.
2. **Offline Pattern Diagnostics**: Flags common dictionary words, simple sequential runs, repeated characters, leetspeak substitutions, and keyboard walks.
3. **Clean, Non-Repetitive Terminal Report**: Presents strengths, weaknesses, prioritized recommendations (max 3), and practical security tips without clutter.
4. **Optional In-Depth Breakdown**: Provides an optional detailed breakdown on request showing points awarded per criterion and a complete security checklist.

---

## Educational Learning Outcomes

This project demonstrates core competencies in cybersecurity and software engineering:
- **Entropy vs. Complexity**: Understanding why a 16-character multi-word passphrase often offers higher entropy and better usability than an 8-character symbol salad.
- **Defensive CLI Engineering**: Employing `getpass` to defeat shoulder-surfing attacks in shared terminal environments, while maintaining graceful fallbacks for non-TTY terminals.
- **Privacy By Design**: Guaranteeing zero disk caching, zero plaintext logging, and zero credential transmission across network interfaces.
- **Terminal Encoding Resilience**: Implementing crash-safe stdout configuration to support Windows PowerShell, Command Prompt, and Unix terminals cleanly.
- **Automated Verification**: Maintaining a 100% standard library test suite (`unittest`) covering boundary conditions, privacy guarantees, and pattern detection.

---

## Features

- **Standard Complexity Evaluation**: Tests length baseline (8+), length bonus (12+), uppercase letters, lowercase letters, digits, and special symbols.
- **Pattern & Heuristic Detection**:
  - Top dictionary and common leaked passwords (offline, curated check).
  - Predictable leetspeak character substitutions (e.g., `p@ssw0rd`).
  - Consecutive character repetition (3+ identical characters in a row).
  - Alphabetical and numerical sequential runs (e.g., `abc`, `123`, `cba`).
  - Predictable keyboard walks (e.g., `qwerty`, `asdfgh`).
- **Clean & Concise Output**:
  - **WHAT IS GOOD?**: Lists only detected strengths.
  - **WHAT NEEDS IMPROVEMENT?**: Lists only detected weaknesses without duplication.
  - **HOW TO IMPROVE?**: Gives top 3 actionable recommendations.
  - **SECURITY TIP**: Concise reminder on password managers and MFA.
  - **Optional Detailed Breakdown**: Access full criteria points and security checklist on request.
- **Privacy-Preserving Input**: Supports masked/hidden terminal input using Python's built-in `getpass` module, with an option for visible input.
- **Zero Sensitive Data Leakage**: The user's input password is never printed in cleartext; input is represented solely by length and masking.
- **Cross-Platform Compatibility**: ASCII-safe terminal formatting ensures zero crashes across Windows, macOS, and Linux terminals.

---

## System Requirements

- **Python**: Python 3.8 or higher (tested on Python 3.8, 3.10, 3.12, and 3.14).
- **Dependencies**: None. Standard library only (`sys`, `io`, `getpass`, `re`, `typing`, `unittest`).

---

## How to Run

### 1. Interactive Application
Run the script directly using Python:
```bash
python password_checker.py
```

You will be presented with input options:
```text
How would you like to enter your test password?
  [1] Hidden input (recommended - characters will not be shown)
  [2] Visible input (standard typing)
  [q] Quit
```

### 2. Backward-Compatible Python Module Import
You can also import and use the core function in your own Python scripts:
```python
from password_checker import check_password_strength

# Traditional 4-tuple unpacking remains 100% compatible
score, label, tips, checks_passed = check_password_strength("MyDummyTestPass1!")
print(f"Score: {score}/100, Level: {label}")
```

---

## How the Scoring System Works

The scoring engine awards points across 5 foundational criteria plus a length bonus:

| Criterion | Requirement | Points Awarded | Max Points |
| :--- | :--- | :---: | :---: |
| **Minimum Length** | At least 8 characters | +20 | 20 |
| **Length Bonus** | At least 12 characters | +10 | 10 |
| **Uppercase Letters** | Contains at least one `A-Z` | +20 | 20 |
| **Lowercase Letters** | Contains at least one `a-z` | +20 | 20 |
| **Numbers** | Contains at least one `0-9` | +20 | 20 |
| **Special Characters** | Contains symbol (`!@#$%^&*` etc.) | +20 | 20 |

### Score Capping & Strength Levels
- **Maximum Possible Score**: Capped at **100** via `min(total_score, 100)`.
- **Strength Categories**:
  - `0 - 40` : **WEAK**
  - `41 - 60` : **MODERATE**
  - `61 - 80` : **STRONG**
  - `81 - 100`: **VERY STRONG**

*Note: The numerical score is an educational estimate of complexity, not a guarantee of security or a percentage probability of safety.*

---

## Sample Terminal Run

Below is an authentic sample run using a safe dummy test password:

```text
==================================================
           PASSWORD STRENGTH CHECKER
==================================================
Analyze your password and learn how to improve it.
Offline evaluation only - your password is never
stored, logged, or transmitted anywhere.
==================================================

How would you like to enter your test password?
  [1] Hidden input (recommended - characters will not be shown)
  [2] Visible input (standard typing)
  [q] Quit
Select an option (1, 2, or q): 2
Enter a test password: SafeDummyPass#2026

==================================================
           PASSWORD STRENGTH CHECKER
==================================================

--------------- SECURITY REPORT -----------------

Strength Score : 100/100
Strength Level : VERY STRONG
Masked Input   : ****************** (18 characters)

WHAT IS GOOD?
  + Meets minimum length requirement (18 characters).
  + Contains 12 or more characters for substantial cryptographic search space.
  + Includes uppercase letters (A-Z).
  + Includes lowercase letters (a-z).
  + Includes numerical digits (0-9).
  + Includes special characters (!@#$...).

WHAT NEEDS IMPROVEMENT?
  + No weaknesses detected based on checked criteria.

HOW TO IMPROVE?
  1. Password meets complexity criteria. Ensure it is unique to this account.
  2. Store credentials securely in a dedicated password manager.
  3. Enable multi-factor authentication (MFA) wherever available.

SECURITY TIP
Use a long, unique password. Store it in a password manager
and enable MFA wherever possible.

==================================================

Check another password? [Y/n] (or 'd' for detailed breakdown):
```

---

## What the Score Can and Cannot Tell You

### What the Score CAN Tell You
- Whether the password satisfies standard complexity guidelines.
- Whether the password reaches modern minimum length recommendations.
- Whether the password contains basic sequential runs, repeated characters, or common keyboard walks.

### What the Score CANNOT Tell You
- **Leaked Status**: This tool does **NOT** query external breach databases. A complex password could still be compromised if it was exposed in a third-party breach.
- **Targeted Guessing Immunity**: A password based on personal information (name, pet, birthday, sports team) may score 100/100 while remaining trivial for a targeted attacker to guess.
- **Server-Side Storage Security**: No password is safe if a website stores credentials in plaintext or uses obsolete hashing algorithms (such as MD5 or unsalted SHA-1).

---

## Privacy and Security Principles

1. **Local Offline Execution**: The program does not make network requests, connect to APIs, or send telemetry.
2. **Zero Storage or Logging**: Test passwords exist only in temporary process memory during analysis and are discarded immediately.
3. **No Cleartext Output**: The terminal report masks user input with asterisks (`*`) and character counts, avoiding exposure to nearby observers or terminal history logs.
4. **Preserved Raw Input**: Inputs are evaluated as-is without silent trimming or modifications, preserving spaces in passphrases.

---

## Running Automated Tests

A dedicated test suite is included in `test_password_checker.py`. Execute tests from the project directory:

```bash
python -m unittest test_password_checker.py
```

The test suite verifies:
- Empty input and graceful prompt loops.
- Weak, medium, strong, and very strong password examples.
- Passwords with leading, trailing, or internal spaces.
- Common password heuristics, repeated characters, and keyboard patterns.
- Predictable leetspeak variations (`p@ssw0rd`).
- Non-ASCII / Unicode input handling.
- Bound checking and score capping at 100.
- Simplified layout sections (`WHAT IS GOOD?`, `WHAT NEEDS IMPROVEMENT?`, `HOW TO IMPROVE?`, `SECURITY TIP`).
- Optional detailed score breakdown display.
- Total absence of cleartext password exposure in output.
- Backward-compatible 4-tuple unpacking.
