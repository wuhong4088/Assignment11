'''
   CY5003 - Assignment 7
   Password Strength Checker
   Spring 2026
   Wu-Hung Hsiao
   Date: February 19, 2026

   Description:
   This program checks the strength of a password. It uses NIST password
   guidelines and OWASP guidelines. It validates passwords against
   personal information. It uses Typeguard for dynamic analysis.

   Programmed by Wu-Hung Hsiao on February 19, 2026.

   -------------------------------------------------------------------------
   References
   Google. (2026). Gemini (Feb 19 version) [Large language model].
       https://gemini.google.com/
       (AI was used to assist in formatting Python documentation.)

   National Institute of Standards and Technology. (n.d.). How do I create 
       a good password? https://www.nist.gov/cybersecurity/how-do-i-create-good-password

   OWASP Foundation. (2023). Authentication cheat sheet. OWASP Cheat Sheet Series. 
       https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
   -------------------------------------------------------------------------
'''

import re
from typeguard import typechecked

MIN_PASSWORD_LENGTH: int = 8
# NIST: list of common passwords to block
COMMON_PASSWORDS: list = [
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "master", "sunshine", "password1", "welcome",
    "iloveyou", "trustno1", "football", "superman", "123123", "654321"
]

class UserInfo:
    '''
    Class for user personal information.
    '''

    def __init__(self, first_name: str, last_name: str,
                 email: str, date_of_birth: str):
        '''
        Start the UserInfo.
        Input:
            first_name (str)
            last_name (str)
            email (str)
            date_of_birth (str) - MM/DD/YYYY format
        Output:
            None
        '''
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.date_of_birth = date_of_birth

    def get_personal_items(self) -> list:
        '''
        Get a list of personal info fragments for checking.
        Input:
            None
        Output:
            list of strings
        '''
        items: list = [self.first_name.lower(), self.last_name.lower()]
        if "@" in self.email:
            items.append(self.email.split("@")[0].lower())
        parts: list = self.date_of_birth.split("/")
        if len(parts) == 3:
            items.append(parts[2])
        return items

# @typechecked: Typeguard checks param types at runtime (dynamic analysis)
@typechecked
def validate_name(name_input: str) -> bool:
    '''
    Validate a name using length validation.
    Input:
        name_input (str)
    Output:
        True if valid, False otherwise
    '''
    is_valid: bool = False
    if len(name_input) < 1 or len(name_input) > 50:
        print("Error: Name must be 1-50 characters.")
    elif not re.match(r'^[a-zA-Z\s\-]+$', name_input): 
        # Edge Case: What if the name has a space before or after the name, maybe use strip 
        print("Error: Name can only have letters, spaces, hyphens.")
    else:
        is_valid = True
    return is_valid


@typechecked
def validate_email(email_input: str) -> bool:
    '''
    Validate an email using type checking.
    Input:
        email_input (str)
    Output:
        True if valid, False otherwise
    '''
    is_valid: bool = False
    pattern: str = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email_input): 
        # Security: Validate Email doesn't check for length of the email
        # Edge Case: What if they enter email@test..com
        is_valid = True
    else:
        print("Error: Invalid email format.")
    return is_valid


@typechecked
def validate_dob(dob_input: str) -> bool:
    '''
    Validate date of birth using range checking.
    Input:
        dob_input (str) - expected MM/DD/YYYY
    Output:
        True if valid, False otherwise
    '''
    is_valid: bool = False
    match = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{4})$', dob_input)
    # Could also do a length check before matching since it should have a length of 8-10
    if not match:
        print("Error: Please use MM/DD/YYYY format.")
    else:
        month: int = int(match.group(1))
        day: int = int(match.group(2))
        year: int = int(match.group(3))
        # range check each value
        if 1 <= month <= 12 and 1 <= day <= 31 and 1900 <= year <= 2026:
            # Edge Case: Includes invalid dates like February 31st
            is_valid = True
        else:
            print("Error: Invalid date range.")
    return is_valid

def has_personal_info(password: str, user: UserInfo) -> bool:
    '''
    Check if password contains personal info (OWASP).
    Input:
        password (str)
        user (UserInfo)
    Output:
        True if personal info found, False otherwise
    '''
    password_lower: str = password.lower()
    items: list = user.get_personal_items()
    for item in items:
        if len(item) >= 2 and item in password_lower:
            # Security: Maybe check that they didn't put month/day in the password as well
            return True
    return False


def _check_nist(password: str) -> int:
    '''
    NIST checks: length and common password.
    Input:
        password (str)
    Output:
        score (int)
    '''
    score: int = 0
    if len(password) >= MIN_PASSWORD_LENGTH:
        score += 1
        print("  [PASS] Length >= 8 [NIST]")
    else:
        print("  [FAIL] Too short [NIST]")
    if len(password) >= 12:
        score += 1
        print("  [PASS] Length >= 12 [NIST]")
    if password.lower() in COMMON_PASSWORDS:
        # I believe this should be looping through common_passwords to check if they're in password.lower()
        score -= 2
        print("  [FAIL] Common password [NIST]")
    else:
        print("  [PASS] Not common [NIST]")
    return score


def _check_owasp(password: str) -> int:
    '''
    OWASP checks: character diversity and repeated chars.
    Input:
        password (str)
    Output:
        score (int)
    '''
    score: int = 0
    checks: list = [
        ("uppercase", "[A-Z]"), ("lowercase", "[a-z]"),
        ("digit", r"\d"),
        ("special", r"[!@#$%^&*()_+\-=\[\]{};:'\",.<>?/\\|`~]")
    ]
    for label, pattern in checks:
        if re.search(pattern, password):
            score += 1
            print(f"  [PASS] Has {label} [OWASP]")
        else:
            print(f"  [FAIL] No {label} [OWASP]")
    # 3 or more same character in a row
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        print("  [FAIL] 3+ repeated chars [OWASP]")
    return score


def check_strength(password: str, user: UserInfo) -> str:
    '''
    Assess the password strength.
    Input:
        password (str)
        user (UserInfo)
    Output:
        "Weak", "Medium", or "Strong"
    '''
    score: int = 0
    score += _check_nist(password)
    score += _check_owasp(password)
    if has_personal_info(password, user):
        score -= 2
        print("  [FAIL] Contains personal info [OWASP]")
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    return "Strong"

def get_valid_name(prompt: str) -> str:
    '''
    Ask user for a name until valid.
    Input:
        prompt (str)
    Output:
        valid name (str)
    '''
    is_valid: bool = False
    user_input: str = ""
    while not is_valid:
        user_input = input(prompt)
        if validate_name(user_input): 
            is_valid = True
    return user_input


def get_valid_email() -> str:
    '''
    Ask user for email until valid.
    Input:
        None
    Output:
        valid email (str)
    '''
    is_valid: bool = False
    user_input: str = ""
    while not is_valid:
        user_input = input("Enter your email: ")
        if validate_email(user_input):
            is_valid = True
    return user_input


def get_valid_dob() -> str:
    '''
    Ask user for date of birth until valid.
    Input:
        None
    Output:
        valid date of birth (str)
    '''
    is_valid: bool = False
    user_input: str = ""
    while not is_valid:
        user_input = input("Enter your DOB (MM/DD/YYYY): ")
        if validate_dob(user_input):
            is_valid = True
    return user_input


def get_password() -> str:
    '''
    Ask user for a password until length is valid.
    Input:
        None
    Output:
        password (str)
    '''
    is_valid: bool = False
    user_input: str = ""
    while not is_valid:
        user_input = input("Enter a password to check: ")
        if len(user_input) < MIN_PASSWORD_LENGTH:
            print(f"Error: Need at least {MIN_PASSWORD_LENGTH} characters.")
            # Security: Code doesn't check for maximum length
        else:
            is_valid = True
    return user_input

def main() -> None:
    '''
    Main function. Loops until user types 'e'.
    '''
    print("-" * 60)
    print("This Python program checks the strength of a password.")
    print("Program name: password_checker_assignment7.py")
    print("Programmed by Wu-Hung Hsiao on February 19, 2026.")
    print("-" * 60)

    user_choice: str = ""
    while user_choice != "e":
        # collect personal info
        first_name: str = get_valid_name("Enter your first name: ")
        last_name: str = get_valid_name("Enter your last name: ")
        email: str = get_valid_email()
        date_of_birth: str = get_valid_dob()
        user: UserInfo = UserInfo(first_name, last_name, email, date_of_birth)

        # get password and check strength
        password: str = get_password()
        print(f">> Password: {'*' * len(password)}")
        rating: str = check_strength(password, user)

        # show result
        print("=" * 60)
        print(f">> Result: Your password is {rating}.")
        print("=" * 60)
        user_choice = input(
            "Type 'e' to exit or press Enter to continue: ").lower().strip()

    print("Goodbye! - Wu-Hung Hsiao")


if __name__ == "__main__":
    main()
    print("\n--- Testing Typeguard Error ---")
    try:
        # send int instead of str to trigger Typeguard
        validate_name(123)
    except Exception as e:
        print(f" Typeguard caught a bug: {e}")
