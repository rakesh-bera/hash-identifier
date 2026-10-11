"""Hash Identifier: guess a hash's type from its length, prefix, and characters."""

import string

# Each rule describes the "shape" of one hash type.
HASH_RULES = [
    {"name": "MD5", "length": 32, "hex": True},
    {"name": "NTLM", "length": 32, "hex": True},
    {"name": "SHA-1", "length": 40, "hex": True},
    {"name": "SHA-224", "length": 56, "hex": True},
    {"name": "SHA-256", "length": 64, "hex": True},
    {"name": "SHA-384", "length": 96, "hex": True},
    {"name": "SHA-512", "length": 128, "hex": True},
    {"name": "bcrypt", "prefixes": ("$2a$", "$2b$", "$2y$"), "length": 60},
    {"name": "Argon2", "prefixes": ("$argon2i$", "$argon2d$", "$argon2id$")},
]


def is_hex(text):
    """Return True if every character is a hexadecimal digit (0-9, a-f)."""
    return all(char in string.hexdigits for char in text)


def rule_matches(text, rule):
    """Return True if the text fits the shape described by one rule."""
    if "prefixes" in rule and not text.startswith(rule["prefixes"]):
        return False
    if "length" in rule and len(text) != rule["length"]:
        return False
    if rule.get("hex") and not is_hex(text):
        return False
    return True


def identify(hash_string):
    """Return a list of hash types that the given string could be."""
    hash_string = hash_string.strip()
    matches = []
    for rule in HASH_RULES:
        if rule_matches(hash_string, rule):
            matches.append(rule["name"])
    return matches


def main():
    user_input = input("Paste a hash: ")
    results = identify(user_input)

    if results:
        print("Possible types:")
        for name in results:
            print(f"  - {name}")
    else:
        print("Unknown hash type.")


if __name__ == "__main__":
    main()