"""
Tests for the Cloudflare AI Gateway and standards integrations.
"""

import json
from unittest.mock import patch, MagicMock

from ailee_core.backends.llm_backend import LLMBackend
from ailee_core.backends.classifier_backend import ClassifierBackend


class TestCloudflareLLMIntegration:
    """Tests the Cloudflare AI Gateway configuration and routing in LLMBackend."""

    def test_cloudflare_api_gateway_request_construction(self, monkeypatch):
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "mock-token-123")
        monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "mock-account-456")
        monkeypatch.setenv("CLOUDFLARE_GATEWAY_ID", "my-test-gateway")
        monkeypatch.setenv("LLM_MODEL", "anthropic/claude-3-opus")

        mock_response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps({
                            "classification_label": "HIGH_RISK_VENDOR",
                            "confidence_score": 0.95,
                            "risk_score": 9.2,
                            "explanation": "Cloudflare-mediated high risk detection.",
                        })
                    }
                }
            ],
            "model": "anthropic/claude-3-opus",
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_reqs = []

        def mock_urlopen(req, timeout=None):
            captured_reqs.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            backend = LLMBackend()
            result = backend.analyze({"vendors": [{"name": "MercenaryCorp"}]})

        # Verify correct result returned
        assert result.classification_label == "HIGH_RISK_VENDOR"
        assert result.confidence_score == 0.95
        assert result.metadata["gateway"] == "cloudflare_ai_gateway"

        # Verify request parameters
        assert len(captured_reqs) == 1
        req = captured_reqs[0]
        assert req.full_url == "https://api.cloudflare.com/client/v4/accounts/mock-account-456/ai/v1/chat/completions"
        assert req.headers["Authorization"] == "Bearer mock-token-123"
        assert req.headers["Cf-aig-gateway-id"] == "my-test-gateway"

        # Verify payload contains correct model and input
        body = json.loads(req.data.decode("utf-8"))
        assert body["model"] == "anthropic/claude-3-opus"
        assert "MercenaryCorp" in body["messages"][1]["content"]

    def test_cloudflare_api_gateway_workers_ai_response_parsing(self, monkeypatch):
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "mock-token-123")
        monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "mock-account-456")

        # Response structure returned by Workers AI direct run
        mock_response_body = {
            "result": {
                "response": json.dumps({
                    "classification_label": "BENIGN_ENTITY",
                    "confidence_score": 0.99,
                    "risk_score": 0.1,
                    "explanation": "Perfectly normal entity analyzed via Workers AI.",
                })
            }
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            backend = LLMBackend()
            result = backend.analyze({"vendors": [{"name": "GoodCorp"}]})

        assert result.classification_label == "BENIGN_ENTITY"
        assert result.confidence_score == 0.99
        assert result.risk_score == 0.1

    def test_cloudflare_api_gateway_alternative_nested_choices(self, monkeypatch):
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "mock-token-123")
        monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "mock-account-456")

        # Response structure with choices nested under result
        mock_response_body = {
            "result": {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps({
                                "classification_label": "MODERATE_RISK_VENDOR",
                                "confidence_score": 0.85,
                                "risk_score": 5.0,
                                "explanation": "Moderate concern.",
                            })
                        }
                    }
                ]
            }
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            backend = LLMBackend()
            result = backend.analyze({"vendors": [{"name": "SuspiciousCorp"}]})

        assert result.classification_label == "MODERATE_RISK_VENDOR"
        assert result.confidence_score == 0.85

    def test_custom_cloudflare_url_with_token(self, monkeypatch):
        """If a custom Cloudflare Gateway URL is provided, token is passed in headers."""
        monkeypatch.setenv("LLM_API_URL", "https://gateway.ai.cloudflare.com/v1/acct-id/gw-id/custom-provider/v1/chat/completions")
        monkeypatch.setenv("LLM_API_KEY", "custom-provider-key")
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token-789")

        mock_response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps({
                            "classification_label": "BENIGN_ENTITY",
                            "confidence_score": 0.90,
                            "risk_score": 1.5,
                            "explanation": "Custom gateway pass.",
                        })
                    }
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_reqs = []

        def mock_urlopen(req, timeout=None):
            captured_reqs.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            backend = LLMBackend()
            result = backend.analyze({"vendors": []})

        assert result.classification_label == "BENIGN_ENTITY"
        assert len(captured_reqs) == 1
        req = captured_reqs[0]
        assert req.headers["Authorization"] == "Bearer custom-provider-key"
        assert req.headers["Cf-aig-authorization"] == "Bearer cf-token-789"


class TestCloudflareClassifierIntegration:
    """Tests ClassifierBackend Cloudflare custom provider integrations."""

    def test_classifier_with_cloudflare_auth(self, monkeypatch):
        monkeypatch.setenv("CLASSIFIER_API_URL", "https://gateway.ai.cloudflare.com/v1/acct/gw/custom-classifier/predict")
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-classifier-token")

        mock_response_body = {
            "classification_label": "SUSPICIOUS_BEACON",
            "confidence_score": 0.94,
            "risk_score": 8.0,
            "explanation": "Custom classifier pattern match.",
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_reqs = []

        def mock_urlopen(req, timeout=None):
            captured_reqs.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            backend = ClassifierBackend()
            result = backend.analyze({"packet_size": 1500})

        assert result.classification_label == "SUSPICIOUS_BEACON"
        assert result.confidence_score == 0.94
        assert result.metadata["gateway"] == "cloudflare_custom_provider"

        assert len(captured_reqs) == 1
        req = captured_reqs[0]
        # Authorization header defaults to cf_token when classifier_api_key is unset
        assert req.headers["Authorization"] == "Bearer cf-classifier-token"
        assert req.headers["Cf-aig-authorization"] == "Bearer cf-classifier-token"
