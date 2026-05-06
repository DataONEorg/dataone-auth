"""Tests for the authentication module."""

from dataone.auth import _echo_inputs


class TestEchoInputs:
    """Test suite for _echo_inputs function."""

    def test_echo_inputs_returns_same_value(self) -> None:
        """Test that _echo_inputs returns the input value unchanged."""
        assert _echo_inputs(42) == 42

    def test_echo_inputs_zero(self) -> None:
        """Test _echo_inputs with zero."""
        assert _echo_inputs(0) == 0

    def test_echo_inputs_negative(self) -> None:
        """Test _echo_inputs with negative integer."""
        assert _echo_inputs(-5) == -5
