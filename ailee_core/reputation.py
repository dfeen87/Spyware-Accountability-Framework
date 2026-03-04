"""
ailee_core/reputation.py - Decentralized Reputation Networks (v3)

Provides a lightweight federated reputation query interface that allows
trusted NGOs and partner organizations to query shared datasets of known
mercenary infrastructure without centralizing the intelligence.

Design principles:
- No central authority: peers are enumerated from configuration.
- HMAC-SHA256 signed requests prevent spoofing.
- Query responses are aggregated locally; raw data never leaves the peer.
- Graceful degradation: if no peers are reachable, local-only results are used.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class ReputationPeer(BaseModel):
    """Describes a trusted peer in the federated reputation network."""
    name: str = Field(..., description="Human-readable name for this peer (e.g., 'NGO-Alpha')")
    url: str = Field(..., description="Base URL for the peer's reputation API endpoint")
    shared_secret: str = Field(
        ...,
        description=(
            "HMAC shared secret for this peer. "
            "Should be exchanged out-of-band via a secure channel."
        ),
    )
    timeout_seconds: int = Field(default=5, description="HTTP request timeout in seconds")


class ReputationEntry(BaseModel):
    """A single reputation record returned by a peer or found locally."""
    entity: str = Field(..., description="The queried entity (domain, IP, vendor name, ASN, etc.)")
    entity_type: Literal["domain", "ip", "vendor", "asn"] = Field(..., description="Type of entity: 'domain', 'ip', 'vendor', 'asn'")
    risk_score: float = Field(
        ..., ge=0.0, le=10.0, description="Peer-assessed risk score (0=benign, 10=highly malicious)"
    )
    tags: List[str] = Field(default_factory=list, description="Associated tags (e.g., 'c2', 'exfil')")
    source_peer: str = Field(default="local", description="Peer that contributed this entry")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of the assessment")


class ReputationQueryResult(BaseModel):
    """Aggregated result of a federated reputation query."""
    entity: str
    entries: List[ReputationEntry] = Field(default_factory=list)
    aggregate_risk_score: float = Field(
        default=0.0, ge=0.0, le=10.0,
        description="Mean risk score across all peer responses"
    )
    peers_queried: int = 0
    peers_responded: int = 0


# ---------------------------------------------------------------------------
# HMAC Request Signing
# ---------------------------------------------------------------------------

def _sign_query(payload: Dict[str, Any], secret: str) -> str:
    """
    Produces an HMAC-SHA256 signature for a query payload.

    The canonical string is the JSON-serialized payload with keys sorted
    alphabetically. This makes signatures deterministic regardless of insertion
    order.

    Returns:
        Hex-encoded HMAC-SHA256 signature.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_signature(payload: Dict[str, Any], secret: str, provided_sig: str) -> bool:
    """Verifies a query signature using constant-time comparison."""
    expected = _sign_query(payload, secret)
    return hmac.compare_digest(expected, provided_sig)


# ---------------------------------------------------------------------------
# Peer Query
# ---------------------------------------------------------------------------

def _query_single_peer(
    peer: ReputationPeer, entity: str, entity_type: str
) -> Optional[ReputationEntry]:
    """
    Sends a signed reputation query to a single peer and returns its response.

    The request format is a JSON POST with:
      { "entity": <str>, "entity_type": <str>, "timestamp": <float>, "nonce": <hex>, "sig": <hex> }

    The peer is expected to return a JSON body matching the ReputationEntry schema.

    Returns:
        A ReputationEntry on success, or None if the peer is unreachable or
        returns an invalid/unsigned response.
    """
    if not peer.url.startswith("https://"):
        logger.error("Peer %s has non-HTTPS URL; refusing to connect.", peer.name)
        return None

    payload = {
        "entity": entity,
        "entity_type": entity_type,
        "timestamp": time.time(),
    }
    payload["nonce"] = secrets.token_hex(16)
    payload["sig"] = _sign_query(payload, peer.shared_secret)

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=f"{peer.url.rstrip('/')}/reputation/query",
        data=body,
        headers={"Content-Type": "application/json", "X-SAF-Peer": "true"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=peer.timeout_seconds) as response:
            raw = json.loads(response.read().decode("utf-8"))
            # Validate peer signature on response
            response_sig = raw.pop("sig", None)
            if response_sig is None or not _verify_signature(raw, peer.shared_secret, response_sig):
                logger.warning("Peer %s returned an unsigned or invalid response; discarding.", peer.name)
                return None
            # Overwrite source_peer with the known peer name (not self-reported)
            raw["source_peer"] = peer.name
            entry = ReputationEntry(**raw)
            return entry
    except urllib.error.URLError as exc:
        logger.info("Peer %s unreachable: %s", peer.name, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected error querying peer %s: %s", peer.name, exc)
        return None


# ---------------------------------------------------------------------------
# Federated Query Orchestrator
# ---------------------------------------------------------------------------

def load_peers_from_env() -> List[ReputationPeer]:
    """
    Loads peer configuration from the ``SAF_REPUTATION_PEERS`` environment
    variable. The variable should be a JSON array of peer objects conforming
    to the ReputationPeer schema.

    Example value::

        [
          {"name": "NGO-Alpha", "url": "https://alpha.example-ngo.org",
           "shared_secret": "change-me-before-use"}
        ]

    Returns:
        A (possibly empty) list of ReputationPeer objects.
    """
    raw = os.environ.get("SAF_REPUTATION_PEERS", "[]")
    try:
        peer_dicts = json.loads(raw)
        return [ReputationPeer(**p) for p in peer_dicts]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse SAF_REPUTATION_PEERS: %s", exc)
        return []


def query_reputation(
    entity: str,
    entity_type: Literal["domain", "ip", "vendor", "asn"] = "domain",
    peers: Optional[List[ReputationPeer]] = None,
) -> ReputationQueryResult:
    """
    Queries the federated reputation network for intelligence about an entity.

    Iterates over all configured peers, sends HMAC-signed queries, and
    aggregates the responses into a single ReputationQueryResult. No raw
    data is forwarded between peers; only the calling node's query is sent.

    If no peers are configured (or all peers are unreachable), the result
    contains an empty entries list with aggregate_risk_score=0.0, allowing
    the calling pipeline to continue with local-only analysis.

    Args:
        entity: The entity to query (e.g., a domain, IP, vendor name).
        entity_type: The type of entity ('domain', 'ip', 'vendor', 'asn').
        peers: Optional explicit list of peers. If None, loaded from env.

    Returns:
        A ReputationQueryResult aggregating all peer responses.
    """
    if peers is None:
        peers = load_peers_from_env()

    result = ReputationQueryResult(entity=entity, peers_queried=len(peers))
    responded = 0

    for peer in peers:
        entry = _query_single_peer(peer, entity, entity_type)
        if entry is not None:
            result.entries.append(entry)
            responded += 1

    result.peers_responded = responded

    if result.entries:
        result.aggregate_risk_score = sum(e.risk_score for e in result.entries) / len(result.entries)

    return result
