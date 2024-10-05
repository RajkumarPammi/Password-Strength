import re

def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    if not re.search("[a-z]", password):
        return "Weak"
    if not re.search("[A-Z]", password):
        return "Weak"
    if not re.search("[0-9]", password):
        return "Weak"
    if not re.search("[@#$%^&+=]", password):
        return "Weak"
    return "Strong"

def suggest_improvements(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase length to at least 8 characters.")
    if not re.search("[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search("[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search("[0-9]", password):
        suggestions.append("Add digits.")
    if not re.search("[@#$%^&+=]", password):
        suggestions.append("Add special characters.")
    return suggestions

def main():
    password = input("Enter a password: ")
    strength = check_password_strength(password)
    print("Password strength:", strength)
    if strength == "Weak":
        print("Suggestions to improve your password:")
        for suggestion in suggest_improvements(password):
            print("-", suggestion)

if __name__ == "__main__":
    main()
