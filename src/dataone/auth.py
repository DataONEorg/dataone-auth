import os
import re


class MissingParameterError(Exception):
    """Raised when a required request parameter is missing."""


def load_client_secrets(filepath: str | None = None) -> dict:
    """Load client secrets from a JSON file.

    Args:
        filepath: Optional explicit path. Falls back to the
                    ``OIDC_CLIENT_SECRETS_FILE`` environment variable

    Returns:
        Parsed dict of client credentials.
    """
    # accept either explicit filepath argument or environment variable, with a default fallback
    resolved = (
        filepath
        or os.getenv("OIDC_CLIENT_SECRETS_FILE")
        or _DEFAULT_SECRETS_PATH
    )
    with open(resolved, "r") as f:
        return json.load(f)


_ORCID_HTTPS_PREFIX = "https://orcid.org/"
_ORCID_HTTP_PREFIX = "http://orcid.org/"

# leave this in as a helper
def extract_orcid(claims: dict | None) -> str | None:
    """Extract a normalised ORCID iD URI from JWT claims.

    Reads the ``orcid`` claim.  The returned value is always the canonical
    HTTPS URI form (``https://orcid.org/XXXX-XXXX-XXXX-XXXX``).

    Args:
        claims: Decoded JWT claims dict, or ``None``.

    Returns:
        Canonical ORCID URI (e.g. ``"https://orcid.org/0000-0002-1825-0097"``),
        or ``None`` if the ``orcid`` claim is absent or malformed.
    """
    if not claims:
        return None

    raw = claims.get("orcid")

    if not raw or not isinstance(raw, str):
        return None

    # Strip http(s)://orcid.org/ prefix, leaving just the bare ID
    if raw.startswith(_ORCID_HTTPS_PREFIX):
        bare = raw[len(_ORCID_HTTPS_PREFIX):]
    elif raw.startswith(_ORCID_HTTP_PREFIX):
        bare = raw[len(_ORCID_HTTP_PREFIX):]
    else:
        bare = raw

    # Validate: XXXX-XXXX-XXXX-XXXX where the last character may be X (checksum digit)
    if not re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{3}[0-9X]", bare):
        return None

    return _ORCID_HTTPS_PREFIX + bare

# probably remove
def get_access_mode() -> str:
    """Get the current access mode from environment.
    
    Returns:
        str: One of 'read_only', 'open', or 'authenticated'. Defaults to 'authenticated'.
    """
    mode = os.getenv("VB_ACCESS_MODE", ACCESS_MODE_AUTHENTICATED).lower()
    if mode not in (ACCESS_MODE_READ_ONLY, ACCESS_MODE_OPEN, ACCESS_MODE_AUTHENTICATED):
        logger.warning(f"Invalid access mode '{mode}', falling back to '{ACCESS_MODE_AUTHENTICATED}'")
        return ACCESS_MODE_AUTHENTICATED
    return mode