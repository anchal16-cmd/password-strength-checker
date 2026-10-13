# ============================================================
# TASK 2: Caesar Cipher Encryption Tool
# CodeOrbit Tech Cybersecurity Internship
# ============================================================
# What it does:
#   Encrypts and decrypts text using the classical Caesar Cipher.
#   Supports user-chosen shift key, brute-force demo, and a menu.
# How to run:
#   python caesar_cipher.py
# No external libraries — only built-in Python.
# ============================================================


# ----------------------------------------------------------
# CORE FUNCTION: encrypt_or_decrypt
# ----------------------------------------------------------
# The Caesar Cipher works by shifting each letter in the
# alphabet by a fixed number (the "key" or "shift value").
#
#  Example with shift = 3:
#    A → D    B → E    Z → C   (wraps around)
#
# Encryption: shift FORWARD by the key.
# Decryption: shift BACKWARD by the key (same as shift 26-key).
#
# Non-letter characters (spaces, digits, punctuation) are
# left unchanged — this preserves readability.
# ----------------------------------------------------------

import sys
import io

# Fix for Windows terminals — ensures emoji and special characters display correctly.
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


def encrypt_or_decrypt(text, shift, mode="encrypt"):
    """
    Encrypt or decrypt a string using the Caesar Cipher.

    Parameters
    ----------
    text  : str  — the input message
    shift : int  — how many positions to shift (0-25)
    mode  : str  — "encrypt" to encode, "decrypt" to decode

    Returns
    -------
    str — the processed message
    """

    result = ""   # We'll build the output character by character

    # For decryption, we simply reverse the shift direction.
    # Shifting forward by (26 - shift) is the same as shifting back.
    if mode == "decrypt":
        shift = 26 - shift   # reverse the shift

    # Ensure the shift stays within the 26-letter alphabet range.
    # The modulo (%) operator handles values > 25 automatically.
    shift = shift % 26

    # ----------------------------------------------------------
    # Loop through every character in the input text
    # ----------------------------------------------------------
    for char in text:

        if char.isalpha():   # Only shift letters; ignore everything else
            # Determine the starting ASCII value for the character's case.
            # ord('A') = 65 for uppercase, ord('a') = 97 for lowercase.
            base = ord('A') if char.isupper() else ord('a')

            # The cipher formula (explained step by step):
            #  1. ord(char) - base  → convert letter to 0-25 range
            #  2. + shift            → apply the shift
            #  3. % 26              → wrap around if we go past Z/z
            #  4. + base            → convert back to ASCII number
            #  5. chr(...)          → convert ASCII number to a character
            shifted_index = (ord(char) - base + shift) % 26
            result += chr(shifted_index + base)

        else:
            # Non-letter character (space, digit, punctuation, etc.)
            # Append it unchanged so the message stays readable.
            result += char

    return result


# ----------------------------------------------------------
# BONUS FUNCTION: brute_force_decrypt
# ----------------------------------------------------------
# In a real attack, if an attacker doesn't know the shift key,
# they can just try all 25 possible shifts and read which one
# makes sense. This is called a "brute-force" attack.
# ----------------------------------------------------------

def brute_force_decrypt(ciphertext):
    """
    Try all 25 possible shifts and display each decrypted attempt.
    The human (or attacker) picks the one that looks like real text.
    """
    print("\n" + "=" * 55)
    print("   🔓  BRUTE-FORCE DECRYPTION (All 25 shifts)")
    print("=" * 55)

    for shift in range(1, 26):   # shifts 1 through 25
        attempt = encrypt_or_decrypt(ciphertext, shift, mode="decrypt")
        print(f"  Shift {shift:>2}: {attempt}")

    print("=" * 55)
    print("  ☝️  Read through the lines above — one will look like")
    print("      real English text. That's the correct decryption!\n")


# ----------------------------------------------------------
# HELPER FUNCTION: get_valid_shift
# ----------------------------------------------------------
# Keeps asking the user for a number until they enter a valid
# integer between 1 and 25.
# ----------------------------------------------------------

def get_valid_shift():
    """Prompt the user for a shift value between 1 and 25."""
    while True:
        try:
            shift = int(input("  Enter shift key (1–25): "))
            if 1 <= shift <= 25:
                return shift
            else:
                print("  ⚠️   Please enter a number between 1 and 25.")
        except ValueError:
            # This catches non-integer input like "abc"
            print("  ⚠️   Invalid input — please enter a whole number.")


# ----------------------------------------------------------
# HELPER FUNCTION: get_text_input
# ----------------------------------------------------------

def get_text_input(prompt):
    """Keep asking until the user types something non-empty."""
    while True:
        text = input(prompt).strip()
        if text:
            return text
        print("  ⚠️   Message cannot be empty. Please try again.")


# ----------------------------------------------------------
# MAIN MENU
# ----------------------------------------------------------

def main():
    """
    Interactive menu loop for the Caesar Cipher tool.
    Keeps running until the user chooses to exit.
    """
    print("\n" + "=" * 55)
    print("   🔐  CAESAR CIPHER ENCRYPTION TOOL")
    print("       CodeOrbit Tech Cybersecurity Internship")
    print("=" * 55)

    while True:
        # Display menu options
        print("\n  What would you like to do?")
        print("  [1]  Encrypt a message")
        print("  [2]  Decrypt a message")
        print("  [3]  Brute-force decrypt (try all shifts)")
        print("  [4]  Quit")
        print()

        choice = input("  Enter your choice (1/2/3/4): ").strip()

        # ------- OPTION 1: Encrypt -------
        if choice == "1":
            print("\n  --- ENCRYPT ---")
            message   = get_text_input("  Enter the message to encrypt: ")
            shift_key = get_valid_shift()

            encrypted = encrypt_or_decrypt(message, shift_key, mode="encrypt")

            print("\n" + "-" * 55)
            print(f"  Original  : {message}")
            print(f"  Shift Key : {shift_key}")
            print(f"  Encrypted : {encrypted}")
            print("-" * 55)

        # ------- OPTION 2: Decrypt -------
        elif choice == "2":
            print("\n  --- DECRYPT ---")
            message   = get_text_input("  Enter the ciphertext to decrypt: ")
            shift_key = get_valid_shift()

            decrypted = encrypt_or_decrypt(message, shift_key, mode="decrypt")

            print("\n" + "-" * 55)
            print(f"  Ciphertext : {message}")
            print(f"  Shift Key  : {shift_key}")
            print(f"  Decrypted  : {decrypted}")
            print("-" * 55)

        # ------- OPTION 3: Brute-force -------
        elif choice == "3":
            print("\n  --- BRUTE-FORCE DECRYPT ---")
            message = get_text_input("  Enter the ciphertext to brute-force: ")
            brute_force_decrypt(message)

        # ------- OPTION 4: Quit -------
        elif choice == "4":
            print("\n  👋  Goodbye! Keep your messages secret!\n")
            break

        # ------- Invalid input -------
        else:
            print("\n  ⚠️   Invalid choice. Please enter 1, 2, 3, or 4.")


# Standard Python entry-point guard
if __name__ == "__main__":
    main()
