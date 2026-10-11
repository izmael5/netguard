"""
Authorization guard.

This module exists to keep the tool pointed only at infrastructure the
operator has explicitly whitelisted (their own devices, lab network, or
websites they own/have written permission to test). Scanning systems you
don't own or lack permission to test is illegal in most jurisdictions
(e.g. the US Computer Fraud and Abuse Act, UK Computer Misuse Act).
"""
import ipaddress
import socket
from config import Config


def _resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def is_authorized(target: str) -> bool:
    """Return True only if `target` matches an allow-listed host/IP/CIDR."""
    allowed = Config.ALLOWED_TARGETS
    target_clean = target.strip().lower()

    for entry in allowed:
        entry = entry.strip().lower()
        if not entry:
            continue
        # Exact hostname / URL-ish match
        if target_clean == entry or target_clean.endswith("://" + entry):
            return True
        # CIDR match
        try:
            network = ipaddress.ip_network(entry, strict=False)
            ip_to_check = _resolve(target_clean) or target_clean
            if ipaddress.ip_address(ip_to_check) in network:
                return True
        except ValueError:
            continue
    return False


class NotAuthorizedError(Exception):
    pass


def require_authorization(target: str):
    if not is_authorized(target):
        raise NotAuthorizedError(
            f"'{target}' is not in allowed_targets. Add it via the "
            f"dashboard or ALLOWED_TARGETS before scanning. Only scan "
            f"systems you own or are explicitly authorized to test."
        )
