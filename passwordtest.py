#!/usr/bin/env python3
import re
import getpass

def check_password_strength(pw: str) -> (str, list):
    """
    Returns a strength rating and list of tips for improvement.
    - Very Strong: length ≥12 and all 4 categories
    - Strong: length ≥10 and ≥3 categories
    - Medium: length ≥8 and ≥2 categories
    - Weak: otherwise
    Categories: lowercase, uppercase, digits, special chars.
    """
    length = len(pw)
    categories = [
        (bool(re.search(r'[a-z]', pw)), "add lowercase letters"),
        (bool(re.search(r'[A-Z]', pw)), "add uppercase letters"),
        (bool(re.search(r'\d', pw)), "add digits"),
        (bool(re.search(r'[^A-Za-z0-9]', pw)), "add special characters")
    ]
    passed = sum(flag for flag, _ in categories)
    tips = [tip for flag, tip in categories if not flag]
    # Length tips
    if length < 8:
        tips.append("use at least 8 characters")
    elif length < 10:
        tips.append("consider using ≥10 characters")
    elif length < 12:
        tips.append("consider using ≥12 characters")

    # Determine rating
    if length >= 12 and passed == 4:
        rating = "Very Strong"
    elif length >= 10 and passed >= 3:
        rating = "Strong"
    elif length >= 8 and passed >= 2:
        rating = "Medium"
    else:
        rating = "Weak"

    return rating, tips

def main():
    pw = getpass.getpass("Enter password to check: ")
    rating, tips = check_password_strength(pw)
    print(f"\nPassword strength: {rating}")
    if tips and rating != "Very Strong":
        print("Suggestions to improve:")
        for tip in tips:
            print(f" • {tip}")

if __name__ == "__main__":
    main()