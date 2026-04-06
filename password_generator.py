#!/usr/bin/env python3
"""
Password Generator - Python Version
Generates strong, random passwords with customizable options.
"""

import argparse
import secrets
import string
import sys


def generate_password(
    length=16,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_special=True,
):
    """
    Generate a random password with specified criteria.
    
    Args:
        length: Password length (default: 16)
        use_uppercase: Include uppercase letters A-Z
        use_lowercase: Include lowercase letters a-z
        use_digits: Include digits 0-9
        use_special: Include special characters
    
    Returns:
        Generated password string
    """
    available_chars = ""
    
    if use_uppercase:
        available_chars += string.ascii_uppercase
    if use_lowercase:
        available_chars += string.ascii_lowercase
    if use_digits:
        available_chars += string.digits
    if use_special:
        available_chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not available_chars:
        raise ValueError("At least one character type must be selected")
    
    if length < 1:
        raise ValueError("Password length must be at least 1")
    
    # Generate password using cryptographically secure random
    password = ''.join(
        secrets.choice(available_chars) for _ in range(length)
    )
    
    return password


def main():
    parser = argparse.ArgumentParser(
        description="Generate strong random passwords",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_generator.py                    # Default: 16 chars with all types
  python password_generator.py -l 32              # 32 character password
  python password_generator.py -l 20 --no-special # No special characters
  python password_generator.py -c 5               # Generate 5 passwords
  python password_generator.py -l 12 --digits-only # Digits only
        """,
    )
    
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=16,
        help="Password length (default: 16)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=1,
        help="Number of passwords to generate (default: 1)",
    )
    parser.add_argument(
        "--no-uppercase",
        action="store_true",
        help="Exclude uppercase letters",
    )
    parser.add_argument(
        "--no-lowercase",
        action="store_true",
        help="Exclude lowercase letters",
    )
    parser.add_argument(
        "--no-digits",
        action="store_true",
        help="Exclude digits",
    )
    parser.add_argument(
        "--no-special",
        action="store_true",
        help="Exclude special characters",
    )
    parser.add_argument(
        "--digits-only",
        action="store_true",
        help="Generate digits only (overrides other options)",
    )
    parser.add_argument(
        "--alphanumeric",
        action="store_true",
        help="Alphanumeric only, no special chars (overrides --no-special)",
    )
    
    args = parser.parse_args()
    
    # Validate length
    if args.length < 1:
        print("Error: Password length must be at least 1", file=sys.stderr)
        sys.exit(1)
    
    # Validate count
    if args.count < 1:
        print("Error: Count must be at least 1", file=sys.stderr)
        sys.exit(1)
    
    # Handle special modes
    use_uppercase = True
    use_lowercase = True
    use_digits = True
    use_special = True
    
    if args.digits_only:
        use_uppercase = False
        use_lowercase = False
        use_digits = True
        use_special = False
    elif args.alphanumeric:
        use_special = False
    else:
        use_uppercase = not args.no_uppercase
        use_lowercase = not args.no_lowercase
        use_digits = not args.no_digits
        use_special = not args.no_special
    
    try:
        # Generate and print passwords
        for i in range(args.count):
            password = generate_password(
                length=args.length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special,
            )
            print(password)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
