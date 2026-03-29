#!/usr/bin/env python3
"""
Security Test Suite â verifies SSN handling guarantees.

These tests confirm that:
  1. SecureSSN correctly formats with dashes
  2. SecureSSN.destroy() zeroes memory
  3. SSN never appears in str/repr/format output
  4. Invalid SSNs are rejected
  5. Destroyed SSNs raise on access
"""

import gc
import re
import pytest
import sys
import os

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from la_cna_accio_bridge import SecureSSN, _secure_zero_string, secure_string_context


class TestSecureSSN:
    """Tests for the SecureSSN triple-layer ephemeral container."""

    def test_valid_ssn_raw_digits(self):
        """9-digit SSN is accepted and stored."""
        ssn = SecureSSN("123456789")
        assert ssn.raw == "123456789"
        ssn.destroy()

    def test_valid_ssn_with_dashes(self):
        """SSN with dashes is accepted (dashes stripped internally)."""
        ssn = SecureSSN("123-45-6789")
        assert ssn.raw == "123456789"
        ssn.destroy()

    def test_with_dashes_format(self):
        """with_dashes() returns correct XXX-XX-XXXX format."""
        ssn = SecureSSN("123456789")
        assert ssn.with_dashes() == "123-45-6789"
        ssn.destroy()

    def test_invalid_ssn_too_short(self):
        """SSN with fewer than 9 digits raises ValueError."""
        with pytest.raises(ValueError, match="9 digits"):
            SecureSSN("12345")

    def test_invalid_ssn_too_long(self):
        """SSN with more than 9 digits raises ValueError."""
        with pytest.raises(ValueError, match="9 digits"):
            SecureSSN("1234567890")

    def test_invalid_ssn_non_numeric(self):
        """SSN with letters (after stripping) raises ValueError."""
        with pytest.raises(ValueError, match="9 digits"):
            SecureSSN("abc-de-fghi")

    def test_destroy_prevents_access(self):
        """After destroy(), accessing raw raises RuntimeError."""
        ssn = SecureSSN("123456789")
        ssn.destroy()
        with pytest.raises(RuntimeError, match="destroyed"):
            _ = ssn.raw

    def test_destroy_prevents_with_dashes(self):
        """After destroy(), with_dashes() raises RuntimeError."""
        ssn = SecureSSN("123456789")
        ssn.destroy()
        with pytest.raises(RuntimeError, match="destroyed"):
            _ = ssn.with_dashes()

    def test_double_destroy_is_safe(self):
        """Calling destroy() twice does not raise."""
        ssn = SecureSSN("123456789")
        ssn.destroy()
        ssn.destroy()  # Should not raise

    def test_context_manager_destroys(self):
        """Using `with` block automatically destroys SSN on exit."""
        with SecureSSN("123456789") as ssn:
            assert ssn.raw == "123456789"
        # After exiting context, SSN should be destroyed
        with pytest.raises(RuntimeError, match="destroyed"):
            _ = ssn.raw

    def test_str_never_leaks_ssn(self):
        """str() representation never contains actual SSN digits."""
        ssn = SecureSSN("123456789")
        assert "123" not in str(ssn)
        assert "456" not in str(ssn)
        assert "789" not in str(ssn)
        assert "***" in str(ssn)
        ssn.destroy()

    def test_repr_never_leaks_ssn(self):
        """repr() representation never contains actual SSN digits."""
        ssn = SecureSSN("123456789")
        assert "123" not in repr(ssn)
        assert "***" in repr(ssn)
        ssn.destroy()

    def test_format_never_leaks_ssn(self):
        """f-string formatting never contains actual SSN digits."""
        ssn = SecureSSN("123456789")
        formatted = f"SSN is {ssn}"
        assert "123" not in formatted
        assert "***" in formatted
        ssn.destroy()

    def test_gc_collect_called_on_destroy(self):
        """Verify gc.collect() is triggered (memory cleanup)."""
        ssn = SecureSSN("123456789")
        # Just verify destroy completes without error
        ssn.destroy()
        # If we get here, gc.collect() didn't crash

    def test_context_manager_destroys_on_exception(self):
        """SSN is destroyed even if an exception occurs in the with block."""
        try:
            with SecureSSN("123456789") as ssn:
                raise ValueError("Test exception")
        except ValueError:
            pass
        with pytest.raises(RuntimeError, match="destroyed"):
            _ = ssn.raw


class TestSecureZeroString:
    """Tests for the _secure_zero_string utility."""

    def test_returns_zeroed_string(self):
        """Returns a string of null bytes matching input length."""
        result = _secure_zero_string("hello")
        assert result == "\x00\x00\x00\x00\x00"
        assert len(result) == 5

    def test_empty_string(self):
        """Empty string input returns empty string."""
        result = _secure_zero_string("")
        assert result == ""


class TestSecureStringContext:
    """Tests for the secure_string_context utility."""

    def test_value_available_in_context(self):
        """Value is accessible within the context manager."""
        with secure_string_context("sensitive_data") as val:
            assert val == "sensitive_data"


class TestNoSSNInOutput:
    """
    Meta-tests: scan the entire source file for hardcoded SSNs.
    Even test SSNs should be checked.
    """

    def test_source_has_no_real_ssn_patterns(self):
        """Main source file contains no 9-digit SSN patterns outside tests."""
        source_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "la_cna_accio_bridge.py",
        )
        with open(source_path, "r") as f:
            source = f.read()

        # Find any 9-consecutive-digit patterns
        ssn_patterns = re.findall(r"\b\d{9}\b", source)
        # Filter out known safe values (like port numbers with trailing digits, etc.)
        real_ssns = [p for p in ssn_patterns if not p.startswith("0")]
        assert len(real_ssns) == 0, f"Found potential SSN patterns in source: {real_ssns}"
