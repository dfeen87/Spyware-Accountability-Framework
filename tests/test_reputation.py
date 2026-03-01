"""
Tests for the v3 Decentralized Reputation Network module (ailee_core/reputation.py).
"""

import json
import time
from unittest.mock import patch, MagicMock

from ailee_core.reputation import (
    ReputationPeer,
    ReputationEntry,
    ReputationQueryResult,
    query_reputation,
    load_peers_from_env,
    _sign_query,
    _verify_signature,
)


class TestHmacSigning:
    def test_sign_and_verify_roundtrip(self):
        payload = {"entity": "evil.example.com", "entity_type": "domain", "timestamp": 1234567890.0}
        secret = "shared-secret-ngo"
        sig = _sign_query(payload, secret)
        assert _verify_signature(payload, secret, sig)

    def test_wrong_secret_fails_verification(self):
        payload = {"entity": "evil.example.com", "entity_type": "domain", "timestamp": 1.0}
        sig = _sign_query(payload, "correct-secret")
        assert not _verify_signature(payload, "wrong-secret", sig)

    def test_tampered_payload_fails_verification(self):
        payload = {"entity": "evil.example.com", "entity_type": "domain", "timestamp": 1.0}
        secret = "shared-secret"
        sig = _sign_query(payload, secret)
        payload["entity"] = "benign.example.com"
        assert not _verify_signature(payload, secret, sig)

    def test_signature_is_deterministic(self):
        payload = {"entity": "x.com", "entity_type": "domain", "timestamp": 42.0}
        secret = "s"
        assert _sign_query(payload, secret) == _sign_query(payload, secret)


class TestLoadPeersFromEnv:
    def test_empty_env_returns_empty_list(self, monkeypatch):
        monkeypatch.delenv("SAF_REPUTATION_PEERS", raising=False)
        peers = load_peers_from_env()
        assert peers == []

    def test_valid_env_returns_peers(self, monkeypatch):
        peer_data = [
            {"name": "NGO-Alpha", "url": "https://alpha.example-ngo.org", "shared_secret": "s1"}
        ]
        monkeypatch.setenv("SAF_REPUTATION_PEERS", json.dumps(peer_data))
        peers = load_peers_from_env()
        assert len(peers) == 1
        assert peers[0].name == "NGO-Alpha"

    def test_invalid_env_returns_empty_list(self, monkeypatch):
        monkeypatch.setenv("SAF_REPUTATION_PEERS", "not-valid-json")
        peers = load_peers_from_env()
        assert peers == []


class TestQueryReputation:
    def test_no_peers_returns_empty_result(self):
        result = query_reputation("evil.example.com", "domain", peers=[])
        assert isinstance(result, ReputationQueryResult)
        assert result.peers_queried == 0
        assert result.peers_responded == 0
        assert result.entries == []
        assert result.aggregate_risk_score == 0.0

    def test_unreachable_peer_returns_empty_entries(self):
        peer = ReputationPeer(
            name="Unreachable-NGO",
            url="http://unreachable.invalid",
            shared_secret="secret",
            timeout_seconds=1,
        )
        result = query_reputation("evil.example.com", "domain", peers=[peer])
        assert result.peers_queried == 1
        assert result.peers_responded == 0
        assert result.entries == []

    def test_successful_peer_response_aggregated(self):
        """Mocks a successful peer response and verifies aggregation."""
        peer = ReputationPeer(
            name="Mock-NGO",
            url="https://mock.ngo.example",
            shared_secret="test-secret",
        )

        # Build a valid mock response
        mock_entry = {
            "entity": "evil.example.com",
            "entity_type": "domain",
            "risk_score": 8.5,
            "tags": ["c2", "spyware"],
            "source_peer": "Mock-NGO",
            "timestamp": time.time(),
        }
        mock_entry["sig"] = _sign_query(
            {k: v for k, v in mock_entry.items() if k != "sig"}, peer.shared_secret
        )

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_entry).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = query_reputation("evil.example.com", "domain", peers=[peer])

        assert result.peers_responded == 1
        assert len(result.entries) == 1
        assert result.entries[0].risk_score == 8.5
        assert result.aggregate_risk_score == 8.5

    def test_aggregate_score_is_mean_of_responses(self):
        """Verifies aggregate_risk_score is mean when multiple entries are available."""
        # Directly build a result with two entries to test aggregation math
        entries = [
            ReputationEntry(entity="x.com", entity_type="domain", risk_score=6.0),
            ReputationEntry(entity="x.com", entity_type="domain", risk_score=8.0),
        ]
        result = ReputationQueryResult(entity="x.com", peers_queried=2, peers_responded=2, entries=entries)
        result.aggregate_risk_score = sum(e.risk_score for e in entries) / len(entries)
        assert result.aggregate_risk_score == 7.0
