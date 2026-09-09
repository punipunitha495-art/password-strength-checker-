# Password Strength Checker

A Python command-line tool that evaluates password strength using
**Shannon entropy calculations** combined with **security policy criteria**
and a **known-leak / dictionary check**.

## Objective

Build password security validation algorithms that calculate entropy and
check policy compliance, then classify the result and give the user
actionable feedback to strengthen their credentials.

## Features

1. **Password policy criteria** — checks length, uppercase, lowercase,
   digits, and special characters.
2. **Entropy calculation** — estimates bits of entropy as
   `length * log2(character_pool_size)`, and checks the password against a
   wordlist of commonly leaked/dictionary passwords (`common_passwords.txt`).
3. **Strength classification** — buckets each password into
   `Weak`, `Moderate`, `Strong`, or `Exceptional`. Any password found in the
   leak list is automatically capped at `Weak`.
4. **Actionable feedback** — concrete suggestions for improving a weak
   or moderate password.

## Usage

```bash
# Interactive mode (input hidden, like a login prompt)
python password_checker.py

# Check a single password directly
python password_checker.py -p "MyP@ssw0rd123"

# Batch-check passwords from a file (one per line)
python password_checker.py -f sample_passwords.txt

# Show plaintext instead of masked output
python password_checker.py -p "MyP@ssw0rd123" --show
```

## Example output

```
============================================================
Password: K9#mQ2$vLp8!zR
------------------------------------------------------------
Length            : 14
Entropy (bits)    : 91.76
Found in leaks?   : No
Policy checks:
  - min_length  : PASS
  - has_upper   : PASS
  - has_lower   : PASS
  - has_digit   : PASS
  - has_special : PASS

Overall Strength  : EXCEPTIONAL
Feedback:
  * No issues found — this password meets all evaluated criteria.
============================================================
```

## Project structure

```
password-strength-checker/
├── password_checker.py     # main program
├── common_passwords.txt    # sample leaked/dictionary wordlist
├── sample_passwords.txt    # example input for batch mode
└── README.md
```

## Notes

- `common_passwords.txt` is a small demonstration wordlist. In a real
  deployment this would be replaced with a full breach corpus (e.g.
  `rockyou.txt`) or a live lookup against the "Have I Been Pwned" Pwned
  Passwords API using the k-anonymity model.
- Entropy is the standard NIST-style estimate: `length × log2(pool size)`,
  where pool size grows with the variety of character classes used.
