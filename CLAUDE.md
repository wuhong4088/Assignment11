# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

CY5003 (Cybersecurity) course repository containing two independent student implementations of a command-line Password Strength Checker. Each student's work lives in its own subdirectory: `Hung/` and `Raymond/`. There are no shared modules, build system, or test suite.

## Running the Programs

```bash
# Hung's implementation (requires typeguard)
pip install typeguard
python Hung/password_checker_assignment7.py

# Raymond's implementation (stdlib only)
python Raymond/password_checker.py
```

Both scripts are interactive CLI programs that loop until the user types `e` to exit.

## Architecture

### Hung (`password_checker_assignment7.py`)

- `UserInfo` class holds personal data (first name, last name, email, DOB in MM/DD/YYYY).
- Input validation functions (`validate_name`, `validate_email`, `validate_dob`) are decorated with `@typechecked` from `typeguard` for runtime type enforcement.
- Strength scoring in `check_strength()` delegates to `_check_nist()` (length ≥ 8 scores +1, ≥ 12 scores +1, common password scores −2) and `_check_owasp()` (uppercase/lowercase/digit/special each score +1, 3+ repeated chars scores −1), then deducts 2 if the password contains personal info fragments.
- Final rating: score ≤ 2 → "Weak", ≤ 4 → "Medium", else "Strong".

### Raymond (`password_checker.py`)

- No classes; personal info (birthday in YYYY-MM-DD, pet name, hometown) is collected into a plain `list` by `get_personal_info()`.
- `validate_input()` handles all user inputs via a `type_flag` parameter: "Birthday" triggers regex pattern matching; anything other than "Password" is sanitized by stripping non-alphanumeric/space characters; all inputs are length-checked (1–100 chars).
- `check_password()` applies a single NIST/CISA rule: 16+ characters is strong; any entry from the bad list found in the password forces it weak. Uses `string.Template` for output formatting.
- Final rating: binary True ("Strong") / False ("Weak").

## Key Differences Between Implementations

| Concern | Hung | Raymond |
|---|---|---|
| Strength output | Three tiers (Weak/Medium/Strong) | Binary (Strong/Weak) |
| Password min length | 8 chars | 16 chars |
| Personal info checked | First name, last name, email prefix, birth year | Birthday string, pet name, hometown |
| Runtime type enforcement | `typeguard` `@typechecked` decorator | `isinstance` check inside `validate_input` |
| DOB format | MM/DD/YYYY | YYYY-MM-DD |
| Sanitization | Not applied to passwords; names/email validated with regex | Non-alphanumeric chars stripped from all fields except passwords |
