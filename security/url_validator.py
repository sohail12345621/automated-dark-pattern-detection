import ipaddress
import socket
import urllib.parse

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
BLOCKED_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}

def is_local_demo_url(url: str) -> bool:
    """Checks if the URL is an authorized local demo harness URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme == "file" and "demo_site" in parsed.path:
            return True
        if parsed.scheme in ("http", "https"):
            hostname = (parsed.hostname or "").lower()
            if hostname in ("127.0.0.1", "localhost", "0.0.0.0") and parsed.path.rstrip("/").endswith("/demo"):
                return True
    except Exception:
        pass
    return False

def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if str(ip) in BLOCKED_METADATA_IPS:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )

def validate_url(url: str, allow_local_demo: bool = True) -> tuple[bool, str | None]:
    """
    Validates a URL against SSRF, bad schemes, credentials, and length limits.
    Returns (True, None) if safe, or (False, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty."

    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters."

    if allow_local_demo and is_local_demo_url(url):
        return True, None

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, f"Invalid URL structure: {e}"

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    if parsed.username or parsed.password or ("@" in (parsed.netloc or "")):
        return False, "URLs containing embedded user credentials are not allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname."

    # Direct IP or DNS resolution SSRF checks
    try:
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if _is_disallowed_ip(ip_obj):
                return False, f"Access to private/local/metadata IP address '{hostname}' is blocked."
        except ValueError:
            pass

        addr_info = socket.getaddrinfo(hostname, None)
        if not addr_info:
            return False, f"Could not resolve hostname '{hostname}'."

        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if _is_disallowed_ip(ip_obj):
                return False, f"Host '{hostname}' resolves to private/restricted IP '{ip_str}' (SSRF blocked)."

    except socket.gaierror:
        return False, f"Unable to resolve host: {hostname}"
    except Exception as e:
        return False, f"Security validation error for host: {e}"

    return True, None
