"""
Client-IP resolution with a trusted-proxy gate.

Single source of truth for "what IP do we attribute this request to" — used
by both the login rate-limiter and the audit log. Previously each route module
had its own `_client_ip` that blindly trusted the first hop of
`X-Forwarded-For`. That let any client spoof the header to (a) bypass the
login rate-limit and (b) poison the forensic audit log with arbitrary IPs.

Security model
--------------
`X-Forwarded-For` is honoured **only** when the direct TCP peer
(`request.client.host`) is a configured trusted proxy. Otherwise the peer
address is authoritative. By default no proxy is trusted, so XFF is ignored
entirely — the safe default for a service bound directly to the network.

Configure trusted proxies via the ``ARGUS_TRUSTED_PROXIES`` environment
variable: a comma-separated list of IPs or CIDRs, e.g.::

    ARGUS_TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8,::1

When the peer is trusted we walk the XFF chain right-to-left and return the
first address that is *not* itself a trusted proxy — i.e. the real client as
seen at the edge of our own infrastructure. Spoofed left-hand entries from an
untrusted client are therefore ignored.
"""

from __future__ import annotations

import os
import ipaddress
from functools import lru_cache
from typing import List

from fastapi import Request

_UNKNOWN = "?"


@lru_cache(maxsize=1)
def _trusted_networks() -> List[ipaddress._BaseNetwork]:
    raw = os.environ.get("ARGUS_TRUSTED_PROXIES", "").strip()
    nets: List[ipaddress._BaseNetwork] = []
    if not raw:
        return nets
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            # Ignore malformed entries rather than fail-open or crash boot.
            continue
    return nets


def _is_trusted(ip_str: str) -> bool:
    nets = _trusted_networks()
    if not nets:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in nets)


def _valid_ip(token: str) -> str:
    """Return the token if it parses as an IP, else _UNKNOWN.

    Strips an optional ``[ipv6]:port`` / ``ipv4:port`` suffix that some
    proxies append, and rejects anything non-IP so the audit log can never be
    poisoned with arbitrary strings.
    """
    token = token.strip()
    if not token:
        return _UNKNOWN
    # Drop a trailing :port on IPv4 (but not on bare IPv6 which has many ':').
    if token.count(":") == 1 and "." in token:
        token = token.split(":", 1)[0]
    token = token.strip("[]")
    try:
        ipaddress.ip_address(token)
        return token
    except ValueError:
        return _UNKNOWN


def client_ip(request: Request) -> str:
    """Resolve the attributable client IP for *request* (trusted-proxy aware)."""
    peer = request.client.host if request.client else None
    if not peer:
        peer = _UNKNOWN

    # Only consult XFF when the immediate peer is a trusted proxy.
    if peer != _UNKNOWN and _is_trusted(peer):
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            # Walk right-to-left; first non-trusted hop is the real client.
            for hop in reversed(xff.split(",")):
                candidate = _valid_ip(hop)
                if candidate == _UNKNOWN:
                    continue
                if not _is_trusted(candidate):
                    return candidate
            # All hops were trusted proxies → fall through to peer.

    return _valid_ip(peer) if peer != _UNKNOWN else _UNKNOWN
