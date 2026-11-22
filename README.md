# Password Checker

A small command-line tool that rates password strength and can check whether a password has shown up in a public data breach.

I built this as a portfolio project while finishing a cybersecurity degree. It is a learning project, not a password manager, and it should not be the only thing you rely on when choosing a password.

## What it does

- Scores a password on length, character variety, common patterns, and a simple entropy estimate
- Prints a rating and a few suggestions
- Optionally checks the Have I Been Pwned Pwned Passwords list using their k-anonymity range API, so the full password (and the full hash) never leave your machine

The password is read with a hidden prompt (`getpass`). Do not pass it as a command-line argument; that would store it in your shell history.

## Why k-anonymity matters

Have I Been Pwned lets you check a password against a large list of breached passwords without sending the password itself.

The tool hashes the password with SHA-1 (that is what the HIBP API uses), then sends only the first five hex characters of the hash. HIBP returns a list of hash suffixes that share that prefix, and the rest of the comparison happens locally. That is k-anonymity: your query matches many possible hashes, so anyone looking at the request cannot tell which password you checked.

## Setup

```bash
git clone https://github.com/B3ardedW3irdo/password-checker.git
cd password-checker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Usage

Rate a password:

```bash
python password_checker.py
```

You will be prompted to type the password. Nothing is echoed to the screen.

Check the Pwned Passwords list as well (needs network access):

```bash
python password_checker.py --breach
```

## How it works

The strength score is a number from 0 to 100, mapped to Very Weak, Weak, Fair, Strong, or Very Strong.

Length and character variety add points. A rough entropy estimate (length times log2 of the character set you actually used) adds a little more if the password is long and mixed. Points come off for common passwords, repeated characters, keyboard walks like `qwerty`, simple sequences like `abcd` or `1234`, and embedded years.

The breach check is separate from the score. A long, mixed password can still be a bad choice if it has already appeared in a breach.

## Tests

```bash
pytest
```

The breach lookup is mocked in the tests, so they can run offline. The strength checks do not need a network.

## Next steps

A few things worth adding later:

- A larger local common-password list, or an offline check against a wordlist
- Scoring closer to how attackers actually guess, along the lines of zxcvbn
- Reading passwords from stdin so you can check several without putting them on the command line

## License

MIT
