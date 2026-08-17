"""Smart password generator that follows website-specific requirements."""

import random
import string
import re
from typing import Dict, Optional, List


class PasswordGenerator:
    """
    Generate passwords following website-specific requirements.

    Analyzes password policy hints from forms and generates compliant,
    properly randomized passwords.
    """

    DEFAULT_LENGTH = 12

    @staticmethod
    def analyze_requirements(
        hint_text: Optional[str] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        **kwargs
    ) -> Dict[str, any]:
        """
        Analyze password requirements from hint text or explicit parameters.

        Args:
            hint_text: Password requirement hint text from the form
            min_length: Minimum password length
            max_length: Maximum password length
            **kwargs: Additional requirements (require_uppercase, require_lowercase,
                     require_digits, require_special, allowed_special_chars, etc.)

        Returns:
            Dictionary of password requirements
        """
        requirements = {
            'min_length': min_length or 8,
            'max_length': max_length or 128,
            'require_uppercase': kwargs.get('require_uppercase', False),
            'require_lowercase': kwargs.get('require_lowercase', False),
            'require_digits': kwargs.get('require_digits', False),
            'require_special': kwargs.get('require_special', False),
            'allowed_special_chars': kwargs.get('allowed_special_chars', '!@#$%^&*()_+-=[]{}|;:,.<>?'),
            'disallowed_chars': kwargs.get('disallowed_chars', ''),
            'no_repeating': kwargs.get('no_repeating', False),
            'no_sequential': kwargs.get('no_sequential', False),
        }

        # Parse hint text if provided
        if hint_text:
            hint_lower = hint_text.lower()

            # Length requirements
            length_match = re.search(r'(\d+)\s*(?:to|\-)\s*(\d+)\s*characters?', hint_lower)
            if length_match:
                requirements['min_length'] = int(length_match.group(1))
                requirements['max_length'] = int(length_match.group(2))
            else:
                min_match = re.search(r'(?:at least|minimum|min)\s*(\d+)\s*characters?', hint_lower)
                if min_match:
                    requirements['min_length'] = int(min_match.group(1))

                max_match = re.search(r'(?:at most|maximum|max)\s*(\d+)\s*characters?', hint_lower)
                if max_match:
                    requirements['max_length'] = int(max_match.group(1))

            # Character type requirements
            if any(word in hint_lower for word in ['uppercase', 'capital', 'upper case']):
                requirements['require_uppercase'] = True

            if any(word in hint_lower for word in ['lowercase', 'lower case']):
                requirements['require_lowercase'] = True

            if any(word in hint_lower for word in ['number', 'digit', 'numeric']):
                requirements['require_digits'] = True

            if any(word in hint_lower for word in ['special', 'symbol', 'character']):
                requirements['require_special'] = True

            # Special character restrictions
            special_chars_match = re.search(r'special characters?:?\s*([!@#$%^&*()_+\-=\[\]{}|;:,.<>?/\\~`\'\"]+)', hint_text)
            if special_chars_match:
                requirements['allowed_special_chars'] = special_chars_match.group(1)

            # Restrictions
            if any(word in hint_lower for word in ['no repeating', 'no repeated', 'no consecutive']):
                requirements['no_repeating'] = True

            if any(word in hint_lower for word in ['no sequential', 'no sequence']):
                requirements['no_sequential'] = True

        return requirements

    @staticmethod
    def generate(
        requirements: Optional[Dict[str, any]] = None,
        length: Optional[int] = None,
        **kwargs
    ) -> str:
        """
        Generate a password following the specified requirements.

        Args:
            requirements: Dictionary of requirements from analyze_requirements()
            length: Desired password length (if not in requirements)
            **kwargs: Override specific requirements

        Returns:
            Generated password string
        """
        if requirements is None:
            requirements = PasswordGenerator.analyze_requirements(**kwargs)

        # Determine password length
        if length is None:
            min_len = requirements.get('min_length', 8)
            max_len = requirements.get('max_length', 128)
            # Use a reasonable default between min and max
            length = max(min_len, min(PasswordGenerator.DEFAULT_LENGTH, max_len))

        # Build character pools
        char_pools = []
        required_chars = []

        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = requirements.get('allowed_special_chars', '!@#$%^&*()_+-=[]{}|;:,.<>?')

        # Remove disallowed characters
        disallowed = requirements.get('disallowed_chars', '')
        if disallowed:
            lowercase = ''.join(c for c in lowercase if c not in disallowed)
            uppercase = ''.join(c for c in uppercase if c not in disallowed)
            digits = ''.join(c for c in digits if c not in disallowed)
            special = ''.join(c for c in special if c not in disallowed)

        # Add required character types
        if requirements.get('require_lowercase', True):
            char_pools.append(lowercase)
            required_chars.append(random.choice(lowercase))
        else:
            char_pools.append(lowercase)

        if requirements.get('require_uppercase', True):
            char_pools.append(uppercase)
            required_chars.append(random.choice(uppercase))
        else:
            char_pools.append(uppercase)

        if requirements.get('require_digits', True):
            char_pools.append(digits)
            required_chars.append(random.choice(digits))

        if requirements.get('require_special', False):
            char_pools.append(special)
            required_chars.append(random.choice(special))

        # Combine all available characters
        all_chars = ''.join(char_pools)

        if not all_chars:
            raise ValueError("No valid characters available for password generation")

        # Generate remaining characters
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [random.choice(all_chars) for _ in range(remaining_length)]

        # Shuffle to randomize positions
        random.shuffle(password_chars)
        password = ''.join(password_chars)

        # Apply restrictions if needed
        if requirements.get('no_repeating', False):
            password = PasswordGenerator._remove_repeating_chars(password, all_chars)

        if requirements.get('no_sequential', False):
            password = PasswordGenerator._remove_sequential_chars(password, all_chars)

        return password

    @staticmethod
    def _remove_repeating_chars(password: str, char_pool: str, max_attempts: int = 50) -> str:
        """Remove repeating consecutive characters."""
        attempts = 0
        while attempts < max_attempts:
            has_repeating = False
            for i in range(len(password) - 1):
                if password[i] == password[i + 1]:
                    has_repeating = True
                    # Replace the repeating character
                    replacement = random.choice(char_pool)
                    while replacement == password[i]:
                        replacement = random.choice(char_pool)
                    password = password[:i+1] + replacement + password[i+2:]
                    break

            if not has_repeating:
                break
            attempts += 1

        return password

    @staticmethod
    def _remove_sequential_chars(password: str, char_pool: str, max_attempts: int = 50) -> str:
        """Remove sequential characters (like 'abc', '123')."""
        attempts = 0
        while attempts < max_attempts:
            has_sequential = False
            for i in range(len(password) - 2):
                if (ord(password[i+1]) == ord(password[i]) + 1 and
                    ord(password[i+2]) == ord(password[i]) + 2):
                    has_sequential = True
                    # Replace the middle character
                    replacement = random.choice(char_pool)
                    while (ord(replacement) == ord(password[i]) + 1 or
                           ord(replacement) == ord(password[i+2]) - 1):
                        replacement = random.choice(char_pool)
                    password = password[:i+1] + replacement + password[i+2:]
                    break

            if not has_sequential:
                break
            attempts += 1

        return password

    @staticmethod
    def generate_from_form_hints(
        form_text: str,
        length: Optional[int] = None
    ) -> str:
        """
        Generate password by analyzing form validation text.

        Args:
            form_text: HTML form text containing password requirements
            length: Optional desired length

        Returns:
            Generated password
        """
        requirements = PasswordGenerator.analyze_requirements(hint_text=form_text)
        return PasswordGenerator.generate(requirements=requirements, length=length)


# Convenience function
def generate_password(
    hint_text: Optional[str] = None,
    min_length: int = 8,
    max_length: int = 128,
    length: Optional[int] = None,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digits: bool = True,
    require_special: bool = False,
    **kwargs
) -> str:
    """
    Generate a secure, randomized password.

    Args:
        hint_text: Password requirement text from website
        min_length: Minimum password length
        max_length: Maximum password length
        length: Specific desired length
        require_uppercase: Require uppercase letters
        require_lowercase: Require lowercase letters
        require_digits: Require digits
        require_special: Require special characters
        **kwargs: Additional requirements

    Returns:
        Generated password string

    Examples:
        >>> # Generate with hint text
        >>> generate_password(hint_text="Password must be 8-16 characters with uppercase, lowercase, and numbers")

        >>> # Generate with explicit requirements
        >>> generate_password(length=12, require_special=True)

        >>> # Generate simple password
        >>> generate_password(length=10, require_special=False)
    """
    requirements = PasswordGenerator.analyze_requirements(
        hint_text=hint_text,
        min_length=min_length,
        max_length=max_length,
        require_uppercase=require_uppercase,
        require_lowercase=require_lowercase,
        require_digits=require_digits,
        require_special=require_special,
        **kwargs
    )
    return PasswordGenerator.generate(requirements=requirements, length=length)
