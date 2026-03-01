"""
Tests for the v3 Live API backend implementations.
Verifies correct fallback to stub logic when env vars are not set,
and correct behavior when env vars point to a mocked endpoint.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from ailee_core.backends.llm_backend import LLMBackend
from ailee_core.backends.classifier_backend import ClassifierBackend


class TestLLMBackendFallback:
    """When no LLM_API_URL/LLM_API_KEY are set, stub logic should run."""

    def test_suspicious_input_classified_high_risk(self, monkeypatch):
        monkeypatch.delenv("LLM_API_URL", raising=False)
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        backend = LLMBackend()
        result = backend.analyze({"vendors": [{"name": "example-spyware corp"}]})
        assert result.classification_label == "HIGH_RISK_VENDOR"
        assert result.metadata["backend"] == "llm_backend_stub"

    def test_benign_input_classified_benign(self, monkeypatch):
        monkeypatch.delenv("LLM_API_URL", raising=False)
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        backend = LLMBackend()
        result = backend.analyze({"vendors": [{"name": "Legit Corp"}]})
        assert result.classification_label == "BENIGN_ENTITY"
        assert result.metadata["backend"] == "llm_backend_stub"


class TestLLMBackendLiveAPI:
    """When env vars are set, the backend should use the live API."""

    def test_live_api_response_parsed(self, monkeypatch):
        monkeypatch.setenv("LLM_API_URL", "https://api.example.com/v1/chat/completions")
        monkeypatch.setenv("LLM_API_KEY", "test-api-key")

        mock_response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps({
                            "classification_label": "HIGH_RISK_VENDOR",
                            "confidence_score": 0.91,
                            "risk_score": 8.8,
                            "explanation": "Detected spyware vendor infrastructure.",
                        })
                    }
                }
            ],
            "model": "gpt-4o-mini",
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            backend = LLMBackend()
            result = backend.analyze({"vendors": [{"name": "EvilCorp"}]})

        assert result.classification_label == "HIGH_RISK_VENDOR"
        assert result.confidence_score == pytest.approx(0.91)
        assert result.metadata.get("backend") == "llm_backend_live"

    def test_live_api_failure_falls_back_to_stub(self, monkeypatch):
        monkeypatch.setenv("LLM_API_URL", "https://api.example.com/v1/chat/completions")
        monkeypatch.setenv("LLM_API_KEY", "test-api-key")

        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            backend = LLMBackend()
            result = backend.analyze({"vendors": [{"name": "example-spyware corp"}]})

        # Should fall back to stub logic
        assert result.classification_label == "HIGH_RISK_VENDOR"
        assert result.metadata["backend"] == "llm_backend_stub"


class TestClassifierBackendFallback:
    """When no CLASSIFIER_API_URL/CLASSIFIER_API_KEY are set, stub logic should run."""

    def test_beaconing_input_classified_suspicious(self, monkeypatch):
        monkeypatch.delenv("CLASSIFIER_API_URL", raising=False)
        monkeypatch.delenv("CLASSIFIER_API_KEY", raising=False)
        backend = ClassifierBackend()
        result = backend.analyze({"tls_fingerprint": "abc123", "timing_interval": 30})
        assert result.classification_label == "SUSPICIOUS_BEACON"
        assert result.metadata["backend"] == "classifier_backend_stub"

    def test_normal_traffic_classified_benign(self, monkeypatch):
        monkeypatch.delenv("CLASSIFIER_API_URL", raising=False)
        monkeypatch.delenv("CLASSIFIER_API_KEY", raising=False)
        backend = ClassifierBackend()
        result = backend.analyze({"protocol": "HTTPS", "dst_port": 443})
        assert result.classification_label == "NORMAL_TRAFFIC"
        assert result.metadata["backend"] == "classifier_backend_stub"


class TestClassifierBackendLiveAPI:
    def test_live_api_response_parsed(self, monkeypatch):
        monkeypatch.setenv("CLASSIFIER_API_URL", "https://classifier.example.com/predict")
        monkeypatch.setenv("CLASSIFIER_API_KEY", "test-key")

        mock_response_body = {
            "classification_label": "SUSPICIOUS_BEACON",
            "confidence_score": 0.95,
            "risk_score": 9.2,
            "explanation": "Live classifier detected C2 beaconing pattern.",
            "metadata": {},
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            backend = ClassifierBackend()
            result = backend.analyze({"tls_fingerprint": "abc123"})

        assert result.classification_label == "SUSPICIOUS_BEACON"
        assert result.confidence_score == pytest.approx(0.95)
        assert result.metadata["backend"] == "classifier_backend_live"

    def test_live_api_failure_falls_back_to_stub(self, monkeypatch):
        monkeypatch.setenv("CLASSIFIER_API_URL", "https://classifier.example.com/predict")
        monkeypatch.setenv("CLASSIFIER_API_KEY", "test-key")

        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            backend = ClassifierBackend()
            result = backend.analyze({"tls_fingerprint": "abc"})

        assert result.classification_label == "SUSPICIOUS_BEACON"
        assert result.metadata["backend"] == "classifier_backend_stub"
