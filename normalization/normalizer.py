import urllib.parse


def normalize_payload(payload: str) -> str:
    """
    Basic normalization pipeline
    """

    if not payload:
        return payload

    # URL decode once
    decoded = urllib.parse.unquote(payload)

    # Double decoding
    decoded = urllib.parse.unquote(decoded)

    # Lowercase normalization
    decoded = decoded.lower()

    return decoded
