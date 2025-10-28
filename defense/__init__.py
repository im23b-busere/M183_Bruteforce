# Defense modules for brute-force protection
# This package contains defense mechanism modules:
#   - delay.py: Linear and progressive delays (3.1)
#   - counter.py: Account lockout after failed attempts (3.2)
#   - logging.py: Authentication logging to DB and file (3.3)
#   - captcha.py: Simple user-interaction challenge (3.2)

from .delay import apply_linear_delay, apply_progressive_delay
from .counter import is_account_locked, increment_failed_attempts, reset_failed_attempts
from .logging import log_auth_attempt
from .captcha import issue_challenge, validate_captcha, clear_challenge

__all__ = [
    'apply_linear_delay',
    'apply_progressive_delay',
    'is_account_locked',
    'increment_failed_attempts',
    'reset_failed_attempts',
    'log_auth_attempt',
    'issue_challenge',
    'validate_captcha',
    'clear_challenge',
]
