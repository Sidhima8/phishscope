import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional


# Blocked CIDR ranges (RFC 1918, RFC 3927 link-local, RFC 6598 CGNAT, Cloud metadata, loopback)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]


def is_ip_safe(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Verify that an IP address is public and does not belong to private/internal/cloud metadata spaces."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        return False, f"Loopback IP address rejected: {ip_str}"
    if ip.is_link_local or str(ip) == "169.254.169.254":
        return False, f"Link-local / Cloud metadata IP address rejected: {ip_str}"
    if ip.is_private:
        return False, f"Internal/Private IP address rejected: {ip_str}"
    if ip.is_reserved:
        return False, f"Reserved IP address rejected: {ip_str}"
    if ip.is_multicast:
        return False, f"Multicast IP address rejected: {ip_str}"

    for blocked in BLOCKED_NETWORKS:
        if ip in blocked:
            return False, f"Blocked network destination: {ip_str} in {blocked}"

    return True, None


def validate_url_for_ssrf(url: str) -> Tuple[bool, Optional[str]]:
    """
    Strictly validates a URL to prevent SSRF before making any outbound HTTP requests.
    Validates scheme, hostname resolution, and destination IP address.
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL"

    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        return False, f"Malformed URL parsing error: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unpermitted URL scheme: {parsed.scheme} (Only http/https allowed)"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL lacks a valid hostname"

    # Block localhost and typical internal aliases
    lowered_host = hostname.lower()
    if lowered_host in ("localhost", "local", "internal", "metadata", "instance-data"):
        return False, f"Host forbidden for security: {hostname}"

    # If hostname is an IP string, check it directly
    try:
        ip_obj = ipaddress.ip_address(lowered_host)
        return is_ip_safe(str(ip_obj))
    except ValueError:
        pass  # It's a domain name, resolve it

    # Resolve domain to IP addresses and verify all resolved IPs
    try:
        addr_info = socket.getaddrinfo(lowered_host, None)
        if not addr_info:
            return False, f"DNS resolution failed for hostname: {hostname}"

        for entry in addr_info:
            ip_candidate = entry[4][0]
            is_safe, reason = is_ip_safe(ip_candidate)
            if not is_safe:
                return False, f"Host {hostname} resolved to forbidden destination {ip_candidate} ({reason})"
    except socket.gaierror as e:
        return False, f"DNS resolution error for {hostname}: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error during host validation: {str(e)}"

    return True, None
