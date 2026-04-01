'''
CY5003
Raymond Ou
Module 7: Assignment
2/20/2026
This program is a Password Checker that compares it to personal information
provided by the user
This continues to loop asking for a new password/personal information unless
they choose to quit by typing e at the specific prompt.
References
Canada, C. S. E. (2024, February). Best practices for passphrases and passwords (ITSAP.30.032).
Canadian Centre for Cyber Security. Retrieved Feb 20, 2026, from
https://www.cyber.gc.ca/en/guidance/best-practices-passphrases-and-passwords-itsap30032

CISA. Formulate Strong Passwords and PIN Codes | CISA. CISA. Retrieved Feb 20, 2026, from
https://www.cisa.gov/resources-tools/training/formulate-strong-passwords-and-pin-codes

Kartik. (2016, -02-20). String Template Class in Python. Geeks for Geeks. Retrieved Feb 20, 2026,
from https://www.geeksforgeeks.org/python/template-class-in-python/

NIST. (2025, August 20). How Do I Create a Good Password? NIST. Retrieved February 20, 2026,
from https://www.nist.gov/cybersecurity/how-do-i-create-good-password

Q/A from:
Anthropic. (2026). Claude (claude-sonnet-4-6) [Large language model]. https://claude.ai

'''
import re # For allowing regular expressions
import string # For Template


def validate_input(response: str, type_flag: str) -> str:
    '''This function validates the input string in 3 ways
    1. Pattern Matching: For Birthday to check for YYYY-MM-DD
    2. Pattern Validation: Checks the pattern of the input
       and strips non alphanumeric characters or spaces.
       Does not sanitize passwords
    3. Length Validation: Checks the length and returns an error if its 0 or more than 100
    4. Type Checking: Makes sure the output after being cleaned is a string
    If the input passes all 3 tests, the santized version is returned
    '''
    clean_response = response
    if type_flag == "Birthday": # Pattern Match
        # Check birthday is in YYYY-MM-DD format
        pattern = r"\d{4}-\d{2}-\d{2}" # 4digits - 2digits - 2 digits
        match = re.search(pattern, response)
        if match is None: # If it finds the correct format
            raise ValueError("The Birthdate is in the wrong format") # Error

    if type_flag != "Password": # Don't sanitize passwords
        # Pattern Matching with Sanitizing the Input by striping non A-Z, numbers or spaces
        clean_response = re.sub('[^A-Za-z0-9 ]+', '', response)

    if len(clean_response) > 100 or len(clean_response) < 1: # Length Validation
        # Error: Question is too long or too short
        raise ValueError("The input has to be between 1 and 100 characters") # Error

    if not isinstance(clean_response, str): # Type Checking if not a string
        # Error: Question couldn't be stored in a string, (shouldn't be possible)
        raise ValueError("Input couldn't be stored in a string") # Error

    # Input Passes all Checks return santized response string
    return clean_response

def check_password(password: str, bad_list: list) -> bool:
    ''' Takes the password and checks it against the list of bad passwords such as pet name, etc.
    Then based on NIST and CISA guidelines checks the length of the password for strength.
    NIST: "NIST guidance recommends that a password should be at least 15 characters long."
    At least 16 characters—longer is stronger!
    Use a random string of mixed-case letters, numbers and symbols
    Another option is to create a memorable phrase of 4 – 7 unrelated words in a passphrase 
    Based on these the main criteria is just that a password needs to be 16 characters or more
    '''
    good_pass = False # Password starts as False (0)
    password = password.lower() # Lower case password for comparisons

    # Check password length, 16+ is good
    if len(password) >= 16:
        good_pass = True

    # Check if any of the bad list values are in the password
    for i in range(0, len(bad_list)): # Check all the entrieds
        check = bad_list[i].lower() # lower case just in case
        if check in password:
            good_pass = False
            t_string = string.Template("$bad_pass found in your password!")
            result = t_string.substitute(bad_pass = bad_list[i])
            print(result)

    return good_pass # Return whether the password was good (True) or bad (False)

def get_personal_info() -> list:
    ''' This function asks the user for their birthday, pet name, and hometown
    to use later to check if they're in their password. password is in by default as well
    Returns the list of bad passwords to check against later
    '''

    lst = ["password"] # List to store responses
    print("Please provide the following information to check against your password") # Intro
    bday = input("What is your birthdate in YYYY-MM-DD format? ") # Birthday
    bday = validate_input(bday, "Birthday") # Check for valid Birthday
    lst.append(bday) # Add to list
    pet = input("What is the name of a pet? ") # Pet Name
    pet = validate_input(pet, "Pet") # Check for valid pet name
    lst.append(pet) # Add to list
    hometown = input("What is the name of your hometown? ") # Hometown
    hometown = validate_input(hometown, "Hometown") # Check for valid hometown
    lst.append(hometown) # Add to list

    return lst # Return responses

def main(): # Main Function
    ''' Main driver for our program that loops until the user inputs an e when prompted.
    '''
    flag = True # Starts asking for password/personal info
    while flag: # Run until flag is false from user typing e
        print("This program checks the strength of a password and checks it "
              + "against personal information") # Intro
        password = input("Please enter your password to check its strength: ") # Ask for password
        password = validate_input(password, "Password") # Validate password
        bad_pass_lst = get_personal_info()
        t_string2 = string.Template("Your password is $strength!")
        if check_password(password, bad_pass_lst):
            result = t_string2.substitute(strength = "Strong")
        else:
            result = t_string2.substitute(strength = "Weak")
        print(result)

        p_info = input("Would you like to try again? Enter anything to continue"
                       + " or e to exit") # Check to quit
        if p_info == "e": # If exiting, set flag to false
            flag = False

if __name__ == '__main__': # Calling Main Function
    main()
    print("This Python program checks the strength of a password and uses "
          + "Scalene, Bandit, and Pylint. Programmed by Raymond Ou on February 20th, 2026.")
