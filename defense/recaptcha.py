"""Google reCAPTCHA integration helpers."""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Optional

# Official Google test keys that always validate against any domain, including localhost.
# These can be overridden by providing RECAPTCHA_SITE_KEY / RECAPTCHA_SECRET_KEY
# environment variables when running the application.
_DEFAULT_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
_DEFAULT_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"

_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def get_site_key() -> str:
    """Return the reCAPTCHA site key used for rendering the widget."""
    return os.getenv("RECAPTCHA_SITE_KEY", _DEFAULT_SITE_KEY)


def _get_secret_key() -> str:
    return os.getenv("RECAPTCHA_SECRET_KEY", _DEFAULT_SECRET_KEY)


def verify_response(response_token: Optional[str], remote_ip: Optional[str] = None) -> bool:
    """Validate a reCAPTCHA response token using Google's verification API."""
    if not response_token:
        return False

    data = {
        "secret": _get_secret_key(),
        "response": response_token,
    }
    if remote_ip:
        data["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(_VERIFY_URL, data=encoded)

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        # Network or decoding error should fail closed.
        return False

    return bool(payload.get("success"))

