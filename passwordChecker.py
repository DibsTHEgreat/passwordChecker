"""
Project: Password Checker
Class: MGT3850: Data Transformation
Author: Divya Pateliya
Submission: May 21st, 2025

Business Problem:
    Threats of hackers stealing confidential data are becoming increasingly more likely, especially as cyberattacks grow in frequency
    and scale of complexity. One of the most common vulnerabilities exploited in these attacks is the use of weak or previously 
    compromised passwords. The goal of this Python script is to ensure users can test their passwords in a safe environment without 
    risking confidential data, while getting guidance on how to build a strong password. It also checks if a password has appeared in 
    any known data breaches using the 'Have I Been Pwned' API, a public and anonymous service for breach detection.
    
    
Main Functionality:
    1. Password Strength Analyzer
    2. Determine how many times your password has appeared in breaches
    
API Citation: https://haveibeenpwned.com/API/v3#Authorisation

"""

# imports
import string
import hashlib
import requests

class PasswordChecker:
    def __init__(self):
        # Super generic list of common passwords which will result in failing score.
        # Grabbed the top 16 most used passwords for this list
        self.common_passwords = [
            "123456", "password", "12345678", "qwerty", "123456789", "1234", "111111", "dragon",
            "123123", "baseball", "football", "monkey", "letmein", "shadow", "master", "qwertyuiop"
        ]
    
    # This functions checks if the password is a common and weak password returns true if the password 
    # is found in the common_passwords; false otherwise.
    def is_generic_password(self, password: str) -> bool:
        return password.lower() in (p.lower() for p in self.common_passwords)
    
    # Checks user password and does basic checks. As certain conditions are met, the score will tally up.
    # The password will have a range of 0 (weak) to 10 (strong).
    def score_password(self, password: str) -> int:
        # Init
        score = 0
        
        # If password is super generic, it will immediately fail with score of 0
        if self.is_generic_password(password):
            return 0

        # More points will be given for longer passwords
        if len(password) >= 8:
            score += 2
        elif len(password) >= 5:
            score += 1

        # Contains any uppercase letters
        if any(c.isupper() for c in password):
            score += 2

        # Contains any lowercase letters
        if any(c.islower() for c in password):
            score += 2

        # Contains any digits
        if any(c.isdigit() for c in password):
            score += 2

        # Contains any symbols
        symbols = set(string.punctuation)
        if any(c in symbols for c in password):
            score += 2

        return score
    
    # This function checks if the user password has been involved in any data breaches returning the # of times 
    # the password was found in breaches, or 0 if not found.
    def check_pwned_password(self, password: str) -> int:
        # Utilizing https://haveibeenpwned.com/API/v3#Authorisation section: Searching by range
        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1password[:5], sha1password[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error: {e}")

        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0

# Outputting a bunch of print statements - Created a function to do this given its repetitive calls
def show_menu():
    print("====================================")
    print("  Welcome to Password Checker")
    print("====================================")
    print("Please choose an option:")
    print("1. Analyze Password Strength")
    print("2. Has My Password Been Leaked?")
    print("3. Exit")
    print("====================================")

# main function
def main():
    checker = PasswordChecker()
    while True:
        show_menu()
        choice = input("Enter your choice (1-3): ").strip()

        # Call your password strength analysis function here
        if choice == '1':
            print("\nYou selected: Analyze Password Strength\n")
            
            password = input("Enter the password to analyze: ").strip()
            score = checker.score_password(password)
            
            print(f"\nPassword Score: {score} / 10")

            if score == 0:
                print("Result: This password is too common or weak. Please choose a stronger password.")
            elif score <= 4:
                print("Result: Weak password. Consider adding uppercase, digits, symbols, or increasing length.")
            elif score <= 7:
                print("Result: Moderate password. Good, but can be improved for better security.")
            else:
                print("Result: Strong password. Well done!")

            print()
            
        # Runs when user wants to check if their password has been breached
        elif choice == '2':
            print("\nYou selected: Has My Password Been Leaked?\n")
            password = input("Enter the password to check: ").strip()
            try:
                leaks = checker.check_pwned_password(password)
                
                if leaks:
                    print(f"\n[!] Warning: Your password has been found {leaks} times in data breaches!")
                    print("You should consider changing it to something more secure.\n")
                else:
                    print("\nGood news — your password was NOT found in known data breaches.\n")
            except Exception as e:
                print(f"\nAn error occurred: {e}\n")
            
        # Exiting program
        elif choice == '3':
            print("\nExiting the program. Stay safe!\n")
            break
        # Invalid Choice - choosing not to break here in case of accidental presses
        else:
            print("\n[!] Invalid choice. Please enter 1, 2, or 3.\n")

if __name__ == "__main__":
    main()