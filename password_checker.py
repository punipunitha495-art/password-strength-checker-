#!/usr/bin/env python3
"""
Password Strength Checker
--------------------------
Evaluates password strength using Shannon entropy calculations combined
with security policy criteria (length, character classes) and checks
against a list of commonly leaked / dictionary passwords.

Usage:
    python password_checker.py                  # interactive mode
    python password_checker.py -p "MyP@ssw0rd"  # single password via CLI
    python password_checker.py -f passwords.txt # batch check from a file

Author: <your name>
"""

import argparse
import getpass
import math
import os
import string
import sys

# ---------------------------------------------------------------------------
# Step 1: Password policy criteria
# ---------------------------------------------------------------------------
POLICY = {
    "min_length": 8,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_special": True,
}

SPECIAL_CHARS = string.punctuation

# A small sample of extremely common / leaked passwords, used to demonstrate
# the "known dictionary leaks" check. In a production tool this list would be
# replaced with a real breach corpus such as the "rockyou.txt" wordlist or a
# call to the "Have I Been Pwned" Pwned Passwords API (k-anonymity model).
COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "common_passwords.txt")


def load_common_passwords(path: str) -> set:
    """Load the dictionary/leak wordlist into a set for O(1) lookups."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


# ---------------------------------------------------------------------------
# Step 1 (cont.): Policy compliance check
# ---------------------------------------------------------------------------
def check_policy(password: str) -> dict:
    """Return a dict of which policy rules pass/fail."""
    return {
        "min_length": len(password) >= POLICY["min_length"],
        "has_upper": any(c.isupper() for c in password),
        "has_lower": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_special": any(c in SPECIAL_CHARS for c in password),
    }


# ---------------------------------------------------------------------------
# Step 2: Entropy calculation + dictionary/leak check
# ---------------------------------------------------------------------------
def calculate_pool_size(password: str) -> int:
    """Estimate the character pool size the password draws from."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in SPECIAL_CHARS for c in password):
        pool += len(SPECIAL_CHARS)
    if any(c.isspace() for c in password):
        pool += 1
    return pool or 1


def calculate_entropy(password: str) -> float:
    """
    Shannon entropy estimate (bits) = length * log2(pool_size)
    This is the standard NIST-style estimate for password strength.
    """
    pool_size = calculate_pool_size(password)
    if len(password) == 0:
        return 0.0
    return round(len(password) * math.log2(pool_size), 2)


def is_leaked(password: str, common_passwords: set) -> bool:
    """Check the password (case-insensitive) against known leaked/dictionary passwords."""
    return password.lower() in common_passwords


# ---------------------------------------------------------------------------
# Step 3: Strength classification
# ---------------------------------------------------------------------------
def classify_strength(entropy: float, policy_results: dict, leaked: bool) -> str:
    """
    Classify into Weak / Moderate / Strong / Exceptional.
    A leaked/dictionary password is automatically capped at Weak,
    regardless of entropy, since it offers no real protection.
    """
    if leaked:
        return "Weak"

    policy_pass_count = sum(policy_results.values())

    if entropy < 28 or policy_pass_count <= 2:
        return "Weak"
    elif entropy < 36 or policy_pass_count <= 3:
        return "Moderate"
    elif entropy < 60:
        return "Strong"
    else:
        return "Exceptional"


# ---------------------------------------------------------------------------
# Step 4: Actionable feedback
# ---------------------------------------------------------------------------
def generate_feedback(password: str, policy_results: dict, leaked: bool) -> list:
    """Produce a list of concrete, actionable suggestions."""
    feedback = []

    if leaked:
        feedback.append(
            "This password appears in known leaked/dictionary password lists. "
            "Do not use it anywhere — choose something unique."
        )
    if not policy_results["min_length"]:
        feedback.append(f"Increase length to at least {POLICY['min_length']} characters.")
    if not policy_results["has_upper"]:
        feedback.append("Add at least one uppercase letter (A-Z).")
    if not policy_results["has_lower"]:
        feedback.append("Add at least one lowercase letter (a-z).")
    if not policy_results["has_digit"]:
        feedback.append("Add at least one digit (0-9).")
    if not policy_results["has_special"]:
        feedback.append(f"Add at least one special character (e.g. {SPECIAL_CHARS[:10]}...).")
    if len(password) < 12 and policy_results["min_length"]:
        feedback.append("Consider using 12+ characters for stronger protection against brute-force attacks.")
    if not feedback:
        feedback.append("No issues found — this password meets all evaluated criteria.")

    return feedback


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def evaluate_password(password: str, common_passwords: set) -> dict:
    policy_results = check_policy(password)
    entropy = calculate_entropy(password)
    leaked = is_leaked(password, common_passwords)
    strength = classify_strength(entropy, policy_results, leaked)
    feedback = generate_feedback(password, policy_results, leaked)

    return {
        "password_length": len(password),
        "entropy_bits": entropy,
        "policy": policy_results,
        "leaked": leaked,
        "strength": strength,
        "feedback": feedback,
    }


def print_report(password_label: str, result: dict) -> None:
    print("=" * 60)
    print(f"Password: {password_label}")
    print("-" * 60)
    print(f"Length            : {result['password_length']}")
    print(f"Entropy (bits)    : {result['entropy_bits']}")
    print(f"Found in leaks?   : {'YES' if result['leaked'] else 'No'}")
    print("Policy checks:")
    for rule, passed in result["policy"].items():
        status = "PASS" if passed else "FAIL"
        print(f"  - {rule:<12}: {status}")
    print(f"\nOverall Strength  : {result['strength'].upper()}")
    print("Feedback:")
    for tip in result["feedback"]:
        print(f"  * {tip}")
    print("=" * 60 + "\n")


def mask(password: str) -> str:
    """Mask a password for display purposes (keep first/last char only)."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("-p", "--password", help="Password to evaluate directly")
    parser.add_argument("-f", "--file", help="Path to a text file with one password per line")
    parser.add_argument("--show", action="store_true", help="Show plaintext password in output (default: masked)")
    args = parser.parse_args()

    common_passwords = load_common_passwords(COMMON_PASSWORDS_FILE)

    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: file not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
        for pw in passwords:
            result = evaluate_password(pw, common_passwords)
            label = pw if args.show else mask(pw)
            print_report(label, result)

    elif args.password:
        result = evaluate_password(args.password, common_passwords)
        label = args.password if args.show else mask(args.password)
        print_report(label, result)

    else:
        # Interactive mode — hides input like a real login prompt
        pw = getpass.getpass("Enter password to evaluate: ")
        result = evaluate_password(pw, common_passwords)
        label = pw if args.show else mask(pw)
        print_report(label, result)


if __name__ == "__main__":
    main()
