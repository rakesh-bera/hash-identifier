"""Hash Identifier: guess a hash's type from its length, prefix, and characters."""

import argparse
import json
import string
import sys

# Each rule describes the "shape" of one hash type, plus what an analyst should know.
# confidence: how sure we are when the shape matches (high / medium / low)
# security:   is this algorithm acceptable for storing passwords today?
HASH_RULES = [
    {"name": "MD5", "length": 32, "hex": True, "confidence": "medium",
     "security": "broken", "note": "Very common, fast, and easy to crack."},
    {"name": "NTLM", "length": 32, "hex": True, "confidence": "low",
     "security": "weak", "note": "Windows password hash. Same shape as MD5."},
    {"name": "SHA-1", "length": 40, "hex": True, "confidence": "medium",
     "security": "broken", "note": "Old standard, collisions have been found."},
    {"name": "SHA-224", "length": 56, "hex": True, "confidence": "medium",
     "security": "fast-hash", "note": "Part of the SHA-2 family."},
    {"name": "SHA-256", "length": 64, "hex": True, "confidence": "medium",
     "security": "fast-hash", "note": "Strong hash, but too fast for passwords."},
    {"name": "SHA-384", "length": 96, "hex": True, "confidence": "medium",
     "security": "fast-hash", "note": "Part of the SHA-2 family."},
    {"name": "SHA-512", "length": 128, "hex": True, "confidence": "medium",
     "security": "fast-hash", "note": "Strong hash, but too fast for passwords."},
    {"name": "bcrypt", "prefixes": ("$2a$", "$2b$", "$2y$"), "length": 60,
     "confidence": "high", "security": "strong",
     "note": "Slow by design, good for passwords."},
    {"name": "Argon2", "prefixes": ("$argon2i$", "$argon2d$", "$argon2id$"),
     "confidence": "high", "security": "strong",
     "note": "Modern password hash, current best practice."},
    {"name": "MD5-crypt", "prefixes": ("$1$",), "confidence": "high",
     "security": "weak", "note": "Old Linux password format."},
    {"name": "SHA-256-crypt", "prefixes": ("$5$",), "confidence": "high",
     "security": "acceptable", "note": "Linux password format."},
    {"name": "SHA-512-crypt", "prefixes": ("$6$",), "confidence": "high",
     "security": "acceptable", "note": "Common Linux password format."},
]

# Lower number = shown first.
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


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


def sort_key(match):
    """Return the number used to sort matches (most confident first)."""
    return CONFIDENCE_ORDER[match["confidence"]]


def identify(hash_string):
    """Return the hash types the string could be, most likely first."""
    hash_string = hash_string.strip()
    matches = []
    for rule in HASH_RULES:
        if rule_matches(hash_string, rule):
            matches.append({
                "name": rule["name"],
                "confidence": rule["confidence"],
                "security": rule["security"],
                "note": rule["note"],
            })
    return sorted(matches, key=sort_key)


def read_hashes_from_file(path):
    """Read one hash per line from a text file, skipping blank lines."""
    with open(path, "r", encoding="utf-8") as file:
        lines = [line.strip() for line in file]
    return [line for line in lines if line]


def build_parser():
    """Describe the command-line options this tool accepts."""
    parser = argparse.ArgumentParser(
        description="Identify the type of a hash by its length, prefix, and characters."
    )
    parser.add_argument("hashes", nargs="*", help="one or more hash strings")
    parser.add_argument("-f", "--file", help="text file with one hash per line")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    return parser


def print_text(results):
    """Print results in a human-friendly layout."""
    for item in results:
        print(item["hash"])
        if not item["matches"]:
            print("  - Unknown hash type")
            continue
        for match in item["matches"]:
            print(f"  - {match['name']}  [{match['confidence']} confidence]")
            print(f"      Security: {match['security']}. {match['note']}")


def main():
    args = build_parser().parse_args()

    hashes = list(args.hashes)
    if args.file:
        try:
            hashes += read_hashes_from_file(args.file)
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not hashes:
        hashes = [input("Paste a hash: ")]

    results = [{"hash": h, "matches": identify(h)} for h in hashes]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_text(results)


if __name__ == "__main__":
    main()