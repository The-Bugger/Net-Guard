"""
Utility validators for NetGuard.

Validates IP addresses (IPv4/IPv6) and numeric setting ranges
before any database or firewall operation is performed.
"""

import ipaddress
from typing import Optional


def validate_ip_address(ip: str) -> bool:
    """
    Validate that a string is a valid IPv4 or IPv6 address.

    Args:
        ip: The IP address string to validate.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def require_valid_ip(ip: str) -> str:
    """
    Validate IP address and raise ValueError with descriptive message if invalid.

    Args:
        ip: The IP address string to validate.

    Returns:
        The original ip string if valid.

    Raises:
        ValueError: If the IP address is not valid IPv4 or IPv6.
    """
    if not validate_ip_address(ip):
        raise ValueError(f"Invalid IP address: {ip}")
    return ip


def validate_integer_range(value: int, min_val: int, max_val: Optional[int] = None) -> bool:
    """
    Validate that an integer is within [min_val, max_val].

    Args:
        value: The integer to validate.
        min_val: Minimum allowed value (inclusive).
        max_val: Maximum allowed value (inclusive). None = no upper bound.

    Returns:
        True if valid, False otherwise.
    """
    if value < min_val:
        return False
    if max_val is not None and value > max_val:
        return False
    return True


def validate_severity(severity: str) -> bool:
    """
    Validate that a severity string is one of the four allowed values.

    Allowed values: Low, Medium, High, Critical

    Args:
        severity: The severity string to validate.

    Returns:
        True if valid, False otherwise.
    """
    ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical"}
    return severity in ALLOWED_SEVERITIES
