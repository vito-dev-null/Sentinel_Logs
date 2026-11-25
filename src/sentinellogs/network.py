from __future__ import annotations

import ipaddress
import re


def validate_bind_host(host: str, *, allow_wildcard: bool = False) -> str:
    value = host.strip()
    if not value or value == "*":
        raise ValueError("Bind host must be an explicit address or hostname")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", value):
            raise ValueError("Bind host must be a valid explicit IP address")
        if any(character.isspace() for character in value):
            raise ValueError("Bind host must not contain whitespace")
        return value

    if address.is_unspecified and not allow_wildcard:
        raise ValueError("Unspecified bind addresses require explicit opt-in")
    return value
