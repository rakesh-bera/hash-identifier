"""Hash Identifier: guess a hash's type from its length, prefix, and characters."""

import argparse
import json
import string
import sys

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
        if item["matches"]:
            for name in item["matches"]:
                print(f"  - {name}")
        else:
            print("  - Unknown hash type")


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