"""
================================================================================
File:        __init__.py
Description: Defense mechanisms package initialization
             Exports all defense functions for easy import
Author:      Cadima Lusiola
Date:        2025-10-28
================================================================================
"""

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
