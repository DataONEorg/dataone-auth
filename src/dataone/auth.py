"""Authentication module for the VegBank API.

Implements OIDC / OAuth 2.0 login via a configurable OIDC provider using authlib.

"""

import logging

# Initialize module-level logger
logger = logging.getLogger(__name__)


def _echo_inputs(value: int) -> int:
    """Echo arguments for testing

    Args:
        value: Integer input to be tested

    Returns:
        Integer value of the argument passed in
    """
    logger.debug("Received input value: %s", value)
    return value
