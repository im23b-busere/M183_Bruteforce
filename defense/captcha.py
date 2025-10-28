"""Simple user-interaction challenge (captcha) for login flow."""
from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import MutableMapping


@dataclass
class CaptchaChallenge:
    token: str
    question: str
    answer: str


def _generate_challenge() -> CaptchaChallenge:
    """Create a simple arithmetic captcha challenge."""
    # Use secrets for unpredictability (cryptographically strong RNG)
    left = secrets.randbelow(9) + 1  # 1..9
    right = secrets.randbelow(9) + 1  # 1..9
    answer = str(left + right)
    token = secrets.token_urlsafe(16)
    question = f"What is {left} + {right}?"
    return CaptchaChallenge(token=token, question=question, answer=answer)


def issue_challenge(session: MutableMapping[str, str]) -> CaptchaChallenge:
    """Generate and store a captcha challenge in the user session."""
    challenge = _generate_challenge()
    session["captcha_token"] = challenge.token
    session["captcha_answer"] = challenge.answer
    return challenge


def clear_challenge(session: MutableMapping[str, str]) -> None:
    """Remove any captcha values from the session."""
    session.pop("captcha_token", None)
    session.pop("captcha_answer", None)


def validate_captcha(
    session: MutableMapping[str, str],
    response: str | None,
    token: str | None,
) -> bool:
    """Validate the provided captcha response against the stored session values."""
    expected_token = session.get("captcha_token")
    expected_answer = session.get("captcha_answer")

    if not expected_token or not expected_answer:
        return False

    if token is None or response is None:
        return False

    if secrets.compare_digest(expected_token, str(token)) and secrets.compare_digest(
        expected_answer,
        str(response).strip(),
    ):
        return True

    return False
