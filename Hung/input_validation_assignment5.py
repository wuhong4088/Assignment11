"""
CY5003
Assignment 5 - Input Validation in Python
Author: Wu-Hung Hsiao
Date: February 4, 2026
Description: 
This program performs input validation on three variables (Age, Email, Password)
using a whitelist approach.
"""

import re
# Constant for minimum password length
MIN_PASSWORD_LENGTH: int = 8

def validate_age(age_input: str) -> bool:
    """
    Function: validate_age
    Input:
        1. age_input (str) - user input for age
    Returns:
        1. bool - True if valid age, False otherwise
    Validates age using whitelist approach: must be integer between 0-120
    """
    is_valid: bool = False
    try:
        # Attempt to convert the string input to an integer
        age = int(age_input)
        # Whitelist: only accept if the integer is within the valid range (0-120)
        if 0 <= age <= 120:
            is_valid = True
        else:
            # Inform the user if the range is invalid
            print("Error: Age must be a valid integer between 0 and 120.")
    except ValueError:
        # Handle cases where input is not a number
        print("Error: Age must be a valid integer between 0 and 120.")
    return is_valid

def validate_email(email_input: str) -> bool:
    """
    Function: validate_email
    Input:
        1. email_input (str) - user input for email
    Returns:
        1. bool - True if valid email format, False otherwise
    Validates email using whitelist approach: must match valid email pattern
    """
    is_valid: bool = False
    # Define the regex pattern for a standard email format
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    # Whitelist: check if the input matches the defined pattern
    if re.match(pattern, email_input):
        is_valid = True
    else:
        print("Error: Invalid email format.")
    return is_valid

def validate_password(password_input: str) -> bool:
    """
    Function: validate_password
    Input:
        1. password_input (str) - user input for password
    Returns:
        1. bool - True if password meets requirements, False otherwise
    Validates password using whitelist approach: min 8 chars with uppercase, lowercase, digit
    """
    is_valid: bool = False
    # Whitelist 1: check if password meets minimum length requirement
    if len(password_input) < MIN_PASSWORD_LENGTH:
        print(f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return is_valid
    # Whitelist 2: check for at least one uppercase letter
    if not re.search(r'[A-Z]', password_input):
        print("Error: Password must contain at least one uppercase letter.")
        return is_valid
    # Whitelist 3: check for at least one lowercase letter
    if not re.search(r'[a-z]', password_input):
        print("Error: Password must contain at least one lowercase letter.")
        return is_valid
    # Whitelist 4: check for at least one digit
    if not re.search(r'\d', password_input):
        print("Error: Password must contain at least one digit.")
        return is_valid
    # If all criteria are passed, mark the password as valid
    is_valid = True
    return is_valid

def get_valid_age() -> int:
    """
    Function: get_valid_age
    Input: None
    Returns: int - valid age from user
    Prompts user for age until valid input is received
    """
    is_valid: bool = False
    user_input: str = "" # Initialize variable
    # Loop until the is_valid flag becomes True
    while not is_valid:
        user_input = input("Please enter your age: ")
        # Call the validation function
        if validate_age(user_input):
            is_valid = True
    return int(user_input)

def get_valid_email() -> str:
    """
    Function: get_valid_email
    Input: None
    Returns: str - valid email from user
    Prompts user for email until valid input is received
    """
    is_valid: bool = False
    # Initialize variable
    user_input: str = ""
    # Loop until the is_valid flag becomes True
    while not is_valid:
        user_input = input("Please enter your email address: ")
        if validate_email(user_input):
            is_valid = True
    return user_input

def get_valid_password() -> str:
    """
    Function: get_valid_password
    Input: None
    Returns: str - valid password from user
    Prompts user for password until valid input is received
    """
    is_valid: bool = False
    # Initialize variable
    user_input: str = ""
    # Loop until the is_valid flag becomes True
    while not is_valid:
        user_input = input("Please enter your password: ")
        if validate_password(user_input):
            is_valid = True
    return user_input

def main() -> None:
    """
    Function: main
    Input: None
    Returns: None
    Main program execution
    """
    # --- ASSIGNMENT REQUIREMENT: Display Program Info ---
    print("-" * 60)
    print("This Python program performs input validation on three variables")
    print("(Age, Email, Password) and uses the Bandit static analyzer.")
    print("Programmed by Wu-Hung Hsiao on February 4, 2026.")
    print("-" * 60)
    print()

    # Get valid age from user
    age = get_valid_age()
    print(f">> Valid age accepted: {age}")
    print()

    # Get valid email from user
    email = get_valid_email()
    print(f">> Valid email accepted: {email}")
    print()

    # Get valid password from user
    password = get_valid_password()
    # Masking password for security in output
    print(f">> Valid password accepted: {'*' * len(password)}")
    print()
    # Display final summary
    print("=" * 60)
    print("Registration Summary:")
    print(f"Age: {age}")
    print(f"Email: {email}")
    # Never print plain text password
    print(f"Password: {'*' * len(password)}")
    print("=" * 60)

if __name__ == "__main__":
    main()