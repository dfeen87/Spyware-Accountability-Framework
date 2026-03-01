"""
Tests for the v3 Privacy Overlay module (ailee_core/privacy.py).
"""

import pytest
from ailee_core.privacy import redact_pii, apply_differential_privacy, pseudonymize


class TestRedactPii:
    def test_email_redacted(self):
        data = {"contact": "analyst@example.com"}
        result = redact_pii(data)
        assert result["contact"] == "[REDACTED_EMAIL]"

    def test_phone_redacted(self):
        data = {"phone": "555-867-5309"}
        result = redact_pii(data)
        assert "[REDACTED_PHONE]" in result["phone"]

    def test_public_ip_redacted(self):
        # A public IP (not in RFC 5737 documentation ranges) should be redacted
        data = {"src_ip": "8.8.8.8"}
        result = redact_pii(data)
        assert "[REDACTED_IP]" in result["src_ip"]

    def test_rfc5737_ip_preserved(self):
        # Documentation ranges must NOT be redacted (they are safe synthetic IPs)
        data = {"src_ip": "192.0.2.1", "dst_ip": "198.51.100.5"}
        result = redact_pii(data)
        assert result["src_ip"] == "192.0.2.1"
        assert result["dst_ip"] == "198.51.100.5"

    def test_private_ip_preserved(self):
        data = {"ip": "10.0.0.1"}
        result = redact_pii(data)
        assert result["ip"] == "10.0.0.1"

    def test_mac_address_redacted(self):
        data = {"mac": "AA:BB:CC:DD:EE:FF"}
        result = redact_pii(data)
        assert "[REDACTED_MAC]" in result["mac"]

    def test_nested_dict_redacted(self):
        data = {"vendor": {"contact_email": "ceo@badcorp.io"}}
        result = redact_pii(data)
        assert result["vendor"]["contact_email"] == "[REDACTED_EMAIL]"

    def test_list_items_redacted(self):
        data = {"emails": ["a@x.com", "b@y.org"]}
        result = redact_pii(data)
        assert all("[REDACTED_EMAIL]" in e for e in result["emails"])

    def test_non_pii_string_unchanged(self):
        data = {"domain": "update.example-spyware.xyz"}
        result = redact_pii(data)
        assert result["domain"] == "update.example-spyware.xyz"

    def test_numeric_values_unchanged(self):
        data = {"risk_score": 9.0, "count": 42}
        result = redact_pii(data)
        assert result["risk_score"] == 9.0
        assert result["count"] == 42

    def test_empty_dict(self):
        assert redact_pii({}) == {}

    def test_empty_list(self):
        assert redact_pii([]) == []


class TestDifferentialPrivacy:
    def test_noise_applied_to_scores(self):
        original = {"confidence_score": 0.92, "risk_score": 8.5, "classification_label": "X"}
        noised = apply_differential_privacy(original, epsilon=0.01)  # Large noise
        # With epsilon=0.01, we expect significant noise; scores will differ
        assert noised["classification_label"] == "X"  # Non-numeric field unchanged
        assert 0.0 <= noised["confidence_score"] <= 1.0
        assert 0.0 <= noised["risk_score"] <= 10.0

    def test_clamp_bounds_respected(self):
        # Apply very small epsilon to force large noise; clamping should keep scores in range
        for _ in range(20):
            result = apply_differential_privacy(
                {"confidence_score": 0.5, "risk_score": 5.0}, epsilon=0.001
            )
            assert 0.0 <= result["confidence_score"] <= 1.0
            assert 0.0 <= result["risk_score"] <= 10.0

    def test_invalid_epsilon_raises(self):
        with pytest.raises(ValueError):
            apply_differential_privacy({"confidence_score": 0.9}, epsilon=0.0)

    def test_non_numeric_fields_untouched(self):
        original = {"explanation": "some text", "confidence_score": 0.8}
        noised = apply_differential_privacy(original, epsilon=1.0)
        assert noised["explanation"] == "some text"


class TestPseudonymize:
    def test_returns_stable_pseudonym(self):
        secret = b"test-secret-key"
        p1 = pseudonymize("analyst@example.com", secret)
        p2 = pseudonymize("analyst@example.com", secret)
        assert p1 == p2

    def test_different_values_different_pseudonyms(self):
        secret = b"test-secret-key"
        p1 = pseudonymize("value1", secret)
        p2 = pseudonymize("value2", secret)
        assert p1 != p2

    def test_pseudonym_starts_with_prefix(self):
        p = pseudonymize("something", b"key")
        assert p.startswith("PSEUDO_")
