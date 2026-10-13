# 🔐 Caesar Cipher Encryption Tool

## What It Does
Encrypts and decrypts text using the **Caesar Cipher** — one of the oldest
encryption techniques. Supports a user-chosen shift key (1–25) and includes
a **brute-force demo** to show why simple ciphers are insecure.

## How the Caesar Cipher Works
Each letter is shifted forward (encrypt) or backward (decrypt) by the key value.
```
Shift = 3:   A → D   B → E   Z → C   Hello → Khoor
```
Non-letter characters (spaces, numbers, punctuation) stay unchanged.

## How to Run
```
python caesar_cipher.py
```
No installation required. Python 3 only. No external libraries.

## Menu Options
```
  [1]  Encrypt a message
  [2]  Decrypt a message
  [3]  Brute-force decrypt (try all shifts)
  [4]  Quit
```

## Sample Run — Encrypt
```
  Enter the message to encrypt: Hello World
  Enter shift key (1–25): 3

  -------------------------------------------------------
  Original  : Hello World
  Shift Key : 3
  Encrypted : Khoor Zruog
  -------------------------------------------------------
```

## Sample Run — Decrypt
```
  Enter the ciphertext to decrypt: Khoor Zruog
  Enter shift key (1–25): 3

  -------------------------------------------------------
  Ciphertext : Khoor Zruog
  Shift Key  : 3
  Decrypted  : Hello World
  -------------------------------------------------------
```

## Sample Run — Brute-force
```
  Enter the ciphertext to brute-force: Khoor Zruog

  Shift  1: Jgnnq Ytnqf
  Shift  2: Ifmmp Xsmpe
  Shift  3: Hello World   ← ✅ This is the real message!
  Shift  4: Gdkkn Vnskc
  ...
```

## 3 Ideas to Stand Out
1. **ROT13 Mode** — Add a preset for ROT13 (shift=13), a popular variant used in forums.
2. **File Encryption** — Let the user encrypt/decrypt a `.txt` file instead of just typed text.
3. **Frequency Analysis Attack** — Show how letter frequency (E is most common in English) can crack the cipher — a real technique used in cryptanalysis.
