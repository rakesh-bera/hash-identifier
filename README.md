# Hash Identifier

A command-line tool that guesses what type of hash a string is by looking at its length, prefix, and characters, then ranks the guesses by confidence and tells you whether the algorithm is safe for storing passwords.

## Why this exists

When you find a hash in a leaked database or a config file, the first question is always "what kind of hash is this?" Everything else, like cracking or verifying it, depends on the answer. This tool answers that question.

## Features

- Identifies 13 hash formats (MD5, NTLM, SHA family, CRC32, bcrypt, Argon2, Linux crypt formats)
- Ranks matches by confidence (high, medium, low)
- Adds a security note to each match (broken, weak, fast-hash, strong)
- Accepts several hashes at once, or a whole file
- Human-readable output, or `--json` for other programs
- Pure Python standard library, nothing to install

## Requirements

- Python 3.10 or newer

## Usage

Identify one hash:

```
python hash_identifier.py 5d41402abc4b2a76b9719d911017c592
```

Output:

```
5d41402abc4b2a76b9719d911017c592
  - MD5  [medium confidence]
      Security: broken. Very common, fast, and easy to crack.
  - NTLM  [low confidence]
      Security: weak. Windows password hash. Same shape as MD5.
```

Identify every hash in a file (one per line):

```
python hash_identifier.py --file hashes.txt
```

Get JSON output:

```
python hash_identifier.py --json 5d41402abc4b2a76b9719d911017c592
```

On Windows PowerShell, wrap hashes that start with `$` in single quotes:

```
python hash_identifier.py '$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
```

## How it works

Each hash type is described by a small rule: its length, whether it is hexadecimal, and an optional prefix such as `$2b$`. The tool checks the input against every rule, keeps the ones that fit, and sorts them by confidence. Adding support for a new hash means adding one entry to `HASH_RULES`.

## Limitations

This tool identifies by shape only. Several algorithms produce hashes with the same length and characters (MD5 and NTLM are both 32 hex characters), so a match means "possible," never "certain." Confidence labels are judgment calls, not guarantees. The tool does not crack or reverse hashes.

## What I learned

- What hashing is and why different algorithms produce different-looking output
- Why fast hashes (MD5, SHA-256) are a poor choice for passwords and slow ones (bcrypt, Argon2) are better
- Writing small single-purpose functions
- Building a command-line interface with `argparse`
- Handling errors cleanly and producing JSON output

## Credit

This project was inspired by the Hash Identifier in [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects). I used it to understand the problem, then wrote my own code from scratch with added confidence ranking, security notes, file input, and JSON output.

## License

MIT, see [LICENSE](LICENSE).