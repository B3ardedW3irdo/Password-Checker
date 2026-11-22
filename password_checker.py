#!/usr/bin/env python3
"""Rate password strength and optionally check Have I Been Pwned."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import re
import string
import sys
from dataclasses import dataclass, field

import requests

# Small local list of passwords that show up in breach reports year after year.
# Not a complete dictionary — just enough to catch the obvious ones offline.
COMMON_PASSWORDS = {
    "password",
    "password1",
    "password12",
    "password123",
    "password1234",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "12345",
    "1234",
    "111111",
    "123123",
    "qwerty",
    "qwerty1",
    "qwerty123",
    "abc123",
    "abcd1234",
    "letmein",
    "welcome",
    "welcome1",
    "admin",
    "admin123",
    "login",
    "master",
    "dragon",
    "monkey",
    "iloveyou",
    "princess",
    "football",
    "baseball",
    "soccer",
    "shadow",
    "sunshine",
    "princess1",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1q2w3e4r",
    "1qaz2wsx",
    "qazwsx",
    "trustno1",
    "whatever",
    "starwars",
    "passw0rd1",
    "changeme",
    "root",
    "toor",
    "guest",
    "test",
    "test123",
}

# Common keyboard walks, plus a few reversed later in the check.
KEYBOARD_SEQUENCES = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "qwerty",
    "asdf",
    "zxcv",
    "1qaz2wsx",
    "1qaz",
    "2wsx",
    "qazwsx",
    "1234567890",
    "123456",
    "abcdef",
)

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
# HIBP asks callers to send a User-Agent and to request padded responses
# so traffic patterns are harder to fingerprint.
HIBP_HEADERS = {
    "User-Agent": "password-checker",
    "Add-Padding": "true",
}

RATING_BANDS = (
    (20, "Very Weak"),
    (40, "Weak"),
    (60, "Fair"),
    (80, "Strong"),
    (101, "Very Strong"),
)


@dataclass
class StrengthResult:
    score: int
    rating: str
    entropy: float
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def character_classes(password: str) -> dict[str, bool]:
    """Which of the four usual character classes show up in the password."""
    return {
        "lower": any(c in string.ascii_lowercase for c in password),
        "upper": any(c in string.ascii_uppercase for c in password),
        "digit": any(c in string.digits for c in password),
        "symbol": any(c not in string.ascii_letters + string.digits for c in password),
    }


def estimate_charset_size(password: str) -> int:
    """Size of the character set implied by the classes actually used.

    Lowercase adds 26, digits add 10, and so on. Symbols are counted as
    the printable punctuation set.
    """
    classes = character_classes(password)
    size = 0
    if classes["lower"]:
        size += 26
    if classes["upper"]:
        size += 26
    if classes["digit"]:
        size += 10
    if classes["symbol"]:
        size += len(string.punctuation)
    return size


def estimate_entropy(password: str) -> float:
    """Rough bits of entropy, assuming random characters from the used set.

    Real passwords are not random, so this is an upper bound, not a promise
    of how long a guess attack would actually take.
    """
    if not password:
        return 0.0
    charset = estimate_charset_size(password)
    if charset <= 1:
        return 0.0
    return len(password) * math.log2(charset)


def is_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS


def has_repeated_chars(password: str, run: int = 3) -> bool:
    """True if the same character appears `run` or more times in a row."""
    if len(password) < run:
        return False
    return bool(re.search(rf"(.)\1{{{run - 1},}}", password, flags=re.IGNORECASE))


def has_sequential_chars(password: str, run: int = 3) -> bool:
    """True if `run` or more letters or digits increment or decrement in order."""
    if len(password) < run:
        return False

    lowered = password.lower()
    for i in range(len(lowered) - run + 1):
        chunk = lowered[i : i + run]
        if not chunk.isalnum():
            continue
        diffs = [ord(chunk[j + 1]) - ord(chunk[j]) for j in range(run - 1)]
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return True
    return False


def has_keyboard_pattern(password: str) -> bool:
    lowered = password.lower()
    for seq in KEYBOARD_SEQUENCES:
        if seq in lowered or seq[::-1] in lowered:
            return True
    return False


def has_year_pattern(password: str) -> bool:
    # Catches things like Winter2024 or password2019, which are common and
    # easy to spray once an attacker knows a name or a company.
    return bool(re.search(r"(?:19|20)\d{2}", password))


def rating_for_score(score: int) -> str:
    for cutoff, label in RATING_BANDS:
        if score < cutoff:
            return label
    return "Very Strong"


def analyze_strength(password: str) -> StrengthResult:
    """Score a password from 0-100 and collect issues plus suggestions."""
    issues: list[str] = []
    suggestions: list[str] = []
    score = 0

    length = len(password)
    if length == 0:
        return StrengthResult(
            score=0,
            rating="Very Weak",
            entropy=0.0,
            issues=["Password is empty."],
            suggestions=["Enter a password to check."],
        )

    # Length does most of the work against brute force, so it carries
    # the largest share of the score.
    if length < 8:
        issues.append("Shorter than 8 characters.")
        suggestions.append("Use at least 12 characters; 16 or more is better.")
    elif length < 12:
        score += 15
        suggestions.append("Aim for 12 or more characters.")
    elif length < 16:
        score += 28
        suggestions.append("A few more characters would help. 16+ is a solid target.")
    else:
        score += 40

    classes = character_classes(password)
    class_count = sum(classes.values())
    if classes["lower"]:
        score += 5
    if classes["upper"]:
        score += 5
    if classes["digit"]:
        score += 5
    if classes["symbol"]:
        score += 10

    if class_count <= 1:
        issues.append("Uses only one type of character.")
        score -= 15
    if not classes["lower"] or not classes["upper"]:
        suggestions.append("Mix uppercase and lowercase letters.")
    if not classes["digit"]:
        suggestions.append("Add a number.")
    if not classes["symbol"]:
        suggestions.append("Add a symbol (for example, ! ? # or -).")

    entropy = estimate_entropy(password)
    if entropy >= 60:
        score += 20
    elif entropy >= 36:
        score += 14
    elif entropy >= 28:
        score += 8

    if is_common_password(password):
        issues.append("This is a very common password.")
        # Even a "complex-looking" common password should not score well.
        score = min(score, 15)
        suggestions.append("Do not use a password that appears on common-password lists.")

    if has_repeated_chars(password):
        issues.append("Contains a run of repeated characters (aaa, 111, ...).")
        score -= 10
        suggestions.append("Avoid repeating the same character several times in a row.")

    if has_sequential_chars(password):
        issues.append("Contains a simple sequence (abc, 123, cba, ...).")
        score -= 10
        suggestions.append("Avoid sequential letters or numbers.")

    if has_keyboard_pattern(password):
        issues.append("Contains a keyboard pattern such as qwerty or asdf.")
        score -= 10
        suggestions.append("Avoid keys that sit next to each other on the keyboard.")

    if has_year_pattern(password):
        issues.append("Contains a year, which is a common guessing target.")
        score -= 5
        suggestions.append("Avoid embedding a year or date of birth.")

    score = max(0, min(100, score))

    # Drop duplicate suggestions while keeping order.
    seen: set[str] = set()
    unique_suggestions = []
    for item in suggestions:
        if item not in seen:
            seen.add(item)
            unique_suggestions.append(item)

    if not issues and score >= 80:
        unique_suggestions = ["Looks solid. A unique password plus a password manager is still the safer habit."]

    return StrengthResult(
        score=score,
        rating=rating_for_score(score),
        entropy=entropy,
        issues=issues,
        suggestions=unique_suggestions,
    )


def hash_for_hibp(password: str) -> tuple[str, str]:
    """SHA-1 the password and split it into the 5-character prefix HIBP expects."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def check_pwned(password: str, session: requests.Session | None = None) -> int:
    """Return how many times this password appears in HIBP's Pwned Passwords list.

    Uses the range API so only the first five hex characters of the SHA-1 hash
    are sent. The response is a list of suffixes that share that prefix; the
    rest of the match happens locally. Returns 0 if it was not found.
    """
    prefix, suffix = hash_for_hibp(password)
    url = HIBP_RANGE_URL.format(prefix=prefix)
    client = session or requests
    response = client.get(url, headers=HIBP_HEADERS, timeout=10)
    response.raise_for_status()

    for line in response.text.splitlines():
        if not line or ":" not in line:
            continue
        candidate, count = line.split(":", 1)
        if candidate.strip().upper() == suffix:
            return int(count.strip())
    return 0


def format_report(result: StrengthResult, pwned_count: int | None = None) -> str:
    lines = [
        f"Rating: {result.rating} ({result.score}/100)",
        f"Entropy: ~{result.entropy:.1f} bits (estimate)",
    ]

    if result.issues:
        lines.append("")
        lines.append("Issues")
        lines.extend(f"- {item}" for item in result.issues)

    if result.suggestions:
        lines.append("")
        lines.append("Suggestions")
        lines.extend(f"- {item}" for item in result.suggestions)

    if pwned_count is not None:
        lines.append("")
        lines.append("Breach check (Have I Been Pwned)")
        if pwned_count > 0:
            times = "time" if pwned_count == 1 else "times"
            lines.append(
                f"- This password has appeared in known breaches {pwned_count:,} {times}."
            )
            lines.append("- Do not use it anywhere. Pick something unique.")
        else:
            lines.append("- No match in the Pwned Passwords list.")
            lines.append("- That is not a guarantee it is safe, only that it was not in this list.")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rate the strength of a password and, optionally, check it against "
            "the Have I Been Pwned Pwned Passwords list. The password is read "
            "with a hidden prompt so it does not end up in your shell history."
        )
    )
    parser.add_argument(
        "--breach",
        action="store_true",
        help="Check the password against Have I Been Pwned (network required).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        password = getpass.getpass("Password: ")
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return 1

    result = analyze_strength(password)

    pwned_count: int | None = None
    if args.breach:
        try:
            pwned_count = check_pwned(password)
        except requests.RequestException as exc:
            print(f"Could not reach Have I Been Pwned: {exc}", file=sys.stderr)
            print(format_report(result))
            return 2

    print(format_report(result, pwned_count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
