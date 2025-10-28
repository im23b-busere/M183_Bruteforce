# Defense 3.2: CAPTCHA (User Interaction Challenge)
# This module implements reCAPTCHA verification to prevent automated attacks

import requests


# Google reCAPTCHA v2 test keys (for development only!)
# Production systems must use their own keys from https://www.google.com/recaptcha/admin
RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
RECAPTCHA_SECRET = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"


def get_site_key():
    """Get the reCAPTCHA site key for frontend integration."""
    return RECAPTCHA_SITE_KEY


def verify_recaptcha(recaptcha_response, client_ip=None, timeout=5.0):
    """Verify reCAPTCHA response with Google's API.
    
    Args:
        recaptcha_response: The g-recaptcha-response token from the client
        client_ip: Optional client IP address for additional verification
        timeout: Request timeout in seconds (default: 5.0)
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    
    Example:
        >>> success, error = verify_recaptcha(token, "127.0.0.1")
        >>> if not success:
        ...     print(f"CAPTCHA failed: {error}")
    """
    if not recaptcha_response:
        return False, "reCAPTCHA response missing"
    
    try:
        verify_data = {
            "secret": RECAPTCHA_SECRET,
            "response": recaptcha_response,
        }
        
        if client_ip:
            verify_data["remoteip"] = client_ip
        
        verify_resp = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data=verify_data,
            timeout=timeout,
        )
        
        result = verify_resp.json()
        
        if result.get("success"):
            return True, None
        else:
            # Extract error codes if available
            error_codes = result.get("error-codes", [])
            error_msg = f"reCAPTCHA verification failed: {', '.join(error_codes)}" if error_codes else "reCAPTCHA verification failed"
            return False, error_msg
            
    except requests.Timeout:
        return False, "reCAPTCHA verification timeout"
    except requests.RequestException as e:
        return False, f"reCAPTCHA verification error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error during reCAPTCHA verification: {str(e)}"


# Legacy interface for compatibility with older code
def issue_challenge(username):
    """Issue a CAPTCHA challenge for a user.
    
    Note: With reCAPTCHA v2, challenges are issued automatically by the frontend.
    This function is provided for API compatibility only.
    
    Returns:
        str: The site key for frontend integration
    """
    return get_site_key()


def validate_captcha(username, captcha_response, client_ip=None):
    """Validate a CAPTCHA response for a user.
    
    Args:
        username: Username attempting authentication (for logging purposes)
        captcha_response: The g-recaptcha-response token from the client
        client_ip: Optional client IP address
    
    Returns:
        bool: True if CAPTCHA is valid, False otherwise
    """
    success, _ = verify_recaptcha(captcha_response, client_ip)
    return success


def clear_challenge(username):
    """Clear any pending CAPTCHA challenge for a user.
    
    Note: With reCAPTCHA v2, there is no server-side challenge state to clear.
    This function is provided for API compatibility only.
    """
    pass  # No-op for reCAPTCHA v2
