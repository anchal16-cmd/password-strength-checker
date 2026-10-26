# 🔐 Password Strength Checker

## What It Does
Analyses a password against 5 security rules and gives it a **score out of 100**
with a strength label (Weak / Moderate / Strong / Very Strong).  
Provides specific improvement tips for any rules the password fails.

## Security Rules Checked
| Rule | Points |
|---|---|
| At least 8 characters | 20 pts |
| At least 12 characters (bonus) | +10 pts |
| Contains an uppercase letter | 20 pts |
| Contains a lowercase letter | 20 pts |
| Contains a digit (0–9) | 20 pts |
| Contains a special character (!@#…) | 20 pts |

## How to Run
```
python password_checker.py
```
No installation required. Python 3 only. No external libraries.

## Sample Run
```
Enter a password to check: hello

==================================================
       PASSWORD STRENGTH REPORT
==================================================
  Password   : he***
  Length     : 5 characters
  Score      : 20/100
  Strength   : 🔴  WEAK

  --- Security Checks ---
  ❌  Length ≥ 8
  ❌  Length ≥ 12 (bonus)
  ❌  Uppercase letter
  ✅  Lowercase letter
  ❌  Digit (0-9)
  ❌  Special character

  --- Improvement Tips ---
  ❌  Use at least 8 characters (longer = stronger).
  💡  Aim for 12+ characters for an even stronger password.
  ❌  Add at least one UPPERCASE letter (e.g. A, B, C …).
  ❌  Include at least one number (0-9).
  ❌  Add a special character like ! @ # $ % ^ & *
==================================================
```

```
Enter a password to check: MyP@ssw0rd#2026

==================================================
       PASSWORD STRENGTH REPORT
==================================================
  Password   : My*************
  Length     : 15 characters
  Score      : 100/100
  Strength   : 🟢  VERY STRONG

  --- Security Checks ---
  ✅  Length ≥ 8
  ✅  Length ≥ 12 (bonus)
  ✅  Uppercase letter
  ✅  Lowercase letter
  ✅  Digit (0-9)
  ✅  Special character

  --- Improvement Tips ---
  ✅  Great password! No improvements needed.
==================================================
```

## 3 Ideas to Stand Out
1. **Password History Check** — Store previously used passwords (hashed) and warn if the user tries to reuse one.
2. **Common Password Blacklist** — Load a file of the 10,000 most common passwords and immediately flag them as weak.
3. **Password Generator** — Add a menu option to auto-generate a strong password that passes all rules.