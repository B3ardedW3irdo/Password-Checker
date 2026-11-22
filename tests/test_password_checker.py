import hashlib
from unittest.mock import Mock

import pytest
import requests

from password_checker import (
    analyze_strength,
    check_pwned,
    estimate_entropy,
    format_report,
    has_keyboard_pattern,
    has_repeated_chars,
    has_sequential_chars,
    has_year_pattern,
    hash_for_hibp,
    is_common_password,
)


def test_empty_password_is_very_weak():
    result = analyze_strength("")
    assert result.score == 0
    assert result.rating == "Very Weak"
    assert result.entropy == 0.0
    assert any("empty" in issue.lower() for issue in result.issues)


def test_short_password_is_weak():
    result = analyze_strength("Ab1!")
    assert result.score < 40
    assert result.rating in {"Very Weak", "Weak"}
    assert any("8 characters" in issue for issue in result.issues)


def test_common_password_is_capped():
    result = analyze_strength("password123")
    assert is_common_password("password123")
    assert result.score <= 15
    assert result.rating == "Very Weak"
    assert any("common" in issue.lower() for issue in result.issues)


def test_common_password_is_case_insensitive():
    assert is_common_password("PaSsWoRd")


def test_long_mixed_password_is_strong():
    # Not a real secret — just a long, mixed string used as a test fixture.
    result = analyze_strength("tr4in-glove!orchid-94Maple")
    assert result.score >= 80
    assert result.rating in {"Strong", "Very Strong"}
    assert not result.issues


def test_entropy_grows_with_length_and_charset():
    short = estimate_entropy("abcdef")
    longer = estimate_entropy("abcdefghijkl")
    mixed = estimate_entropy("Abcdef12")
    assert longer > short
    assert mixed > estimate_entropy("abcdefgh")


def test_repeated_characters():
    assert has_repeated_chars("aaaXYZ")
    assert has_repeated_chars("pass111word")
    assert not has_repeated_chars("ababab")


def test_sequential_characters():
    assert has_sequential_chars("abcToken")
    assert has_sequential_chars("pass1234")
    assert has_sequential_chars("cbaword")
    assert not has_sequential_chars("a1b2c3")


def test_keyboard_pattern():
    assert has_keyboard_pattern("qwertyAdmin")
    assert has_keyboard_pattern("ytrewq")  # reversed
    assert not has_keyboard_pattern("correct-horse-battery")


def test_year_pattern():
    assert has_year_pattern("Winter2024")
    assert has_year_pattern("pw1999")
    assert not has_year_pattern("no-date-here")


def test_single_character_class_is_penalized():
    letters_only = analyze_strength("longpasswordwithoutvariety")
    mixed = analyze_strength("Long-Password-With-Variety-92")
    assert any("one type" in issue for issue in letters_only.issues)
    assert mixed.score > letters_only.score


def test_suggestions_mention_missing_classes():
    result = analyze_strength("abcdefghijkl")
    joined = " ".join(result.suggestions).lower()
    assert "uppercase" in joined or "lowercase" in joined
    assert "number" in joined
    assert "symbol" in joined


def test_hash_for_hibp_splits_sha1():
    prefix, suffix = hash_for_hibp("password")
    digest = hashlib.sha1(b"password").hexdigest().upper()
    assert prefix == digest[:5]
    assert suffix == digest[5:]
    assert len(prefix) == 5


def test_check_pwned_finds_a_match(monkeypatch):
    prefix, suffix = hash_for_hibp("password123")
    body = f"00ABCDE1234567890ABCDEF123456:2\r\n{suffix}:3342\r\nFFFFEEEEAAAA1111222233334444:1\r\n"

    mock_response = Mock()
    mock_response.text = body
    mock_response.raise_for_status = Mock()

    mock_session = Mock()
    mock_session.get.return_value = mock_response

    count = check_pwned("password123", session=mock_session)

    assert count == 3342
    mock_session.get.assert_called_once()
    args, kwargs = mock_session.get.call_args
    assert args[0].endswith(prefix)
    assert kwargs["headers"]["Add-Padding"] == "true"


def test_check_pwned_returns_zero_when_absent():
    mock_response = Mock()
    mock_response.text = "AAAAABBBBBCCCCCDDDDDEEEEEEFFFF:9\r\n"
    mock_response.raise_for_status = Mock()

    mock_session = Mock()
    mock_session.get.return_value = mock_response

    assert check_pwned("unique-not-in-list", session=mock_session) == 0


def test_check_pwned_raises_on_http_error():
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.HTTPError("boom")

    mock_session = Mock()
    mock_session.get.return_value = mock_response

    with pytest.raises(requests.HTTPError):
        check_pwned("password", session=mock_session)


def test_format_report_includes_breach_hit():
    result = analyze_strength("password123")
    report = format_report(result, pwned_count=100)
    assert "Very Weak" in report
    assert "100" in report
    assert "Breach check" in report


def test_format_report_without_breach_omits_section():
    result = analyze_strength("password123")
    report = format_report(result)
    assert "Breach check" not in report
