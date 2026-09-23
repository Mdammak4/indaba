"""Component C4: Risk monitor — one more independent signal, combined with
C1-C3 rather than trusted alone.

Two modes, selected automatically:

1. **Remote** -- if ``SENTINEL_LEARNED_MONITOR_URL`` is set (pointing at a
   running instance of the ``learned-monitor`` starter kit, or your own
   trained model), C4 calls it and uses its returned risk score.
2. **Local heuristic fallback** (default, no network, no training data
   required) -- a small set of hand-picked numeric features, combined with
   fixed weights into a 0-1 score via a logistic squash. This is
   deliberately transparent: every weight below is a calibration choice,
   not a derived constant, and should be reported as such in the ablation
   section of the technical report (e.g. "C4 off" = always contribute 0).

C4 never overrides C1-C3 on its own -- decision.py only escalates on C4's
score when nothing more specific already fired. Its purpose is to catch the
run that is *cumulatively* suspicious without any single hard rule tripping:
several borderline-but-technically-allowed actions in a row.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

import httpx

from app.c1_authority import AuthorityResult
from app.c2_policy import PolicyResult
from app.c3_content import ContentResult
from app.models import CandidateAction, DefenseRequest
from app.session_state import SessionState
from app.tagger import TaggedRequest

MONITOR_URL_ENV = "SENTINEL_LEARNED_MONITOR_URL"
REMOTE_TIMEOUT_SECONDS = 0.5  # never let an unreachable monitor stall a decision

# Calibration weights for the local fallback. Each feature is already
# normalized to roughly [0, 1]; weights are relative importance, tuned by
# hand against the published scenario set, not learned. Report this
# explicitly as a limitation: a trained classifier (the learned-monitor kit)
# would set these from data instead.
FEATURE_WEIGHTS = {
    "action_risk": 1.6,  # tagger's own 0-100 risk score, normalized
    "authority_violation": 1.3,  # C1 fired
    "policy_escalation": 1.1,  # C2 wants to escalate
    "content_flag": 1.4,  # C3 found something (even below block threshold)
    "cumulative_session_risk": 0.9,  # session-level, catches slow-building attacks
    "least_trusted_seen": 0.4,  # how untrusted the worst thing seen so far is
}
BIAS = -2.2  # keeps a fully-clean action's score near 0


@dataclass
class MonitorResult:
    score: float  # 0.0-1.0
    source: str  # "remote" | "local_heuristic" | "local_heuristic_fallback"
    reason_code: str = "ELEVATED_RISK_SCORE"


TRUST_RANK = {
    "system_policy": 0,
    "authenticated_user": 1,
    "trusted_internal": 2,
    "untrusted_internal": 3,
    "untrusted_external": 4,
    "adversary_controlled": 5,
}


def _features(
    action: CandidateAction,
    request: DefenseRequest,
    tagged: TaggedRequest,
    session: SessionState,
    authority: AuthorityResult,
    policy: PolicyResult,
    content: ContentResult,
) -> dict[str, float]:
    action_risk = (tagged.action_identity.risk_score if tagged.action_identity else 0.0) / 100.0
    least_trusted = request.history_digest.least_trusted_seen
    least_trusted_rank = TRUST_RANK.get(least_trusted, 0) / 5.0 if least_trusted else 0.0
    return {
        "action_risk": action_risk,
        "authority_violation": 1.0 if authority.score > 0 else 0.0,
        "policy_escalation": 1.0 if policy.decision == "escalate" else 0.0,
        "content_flag": min(content.score, 1.0),
        "cumulative_session_risk": min(session.cumulative_risk / 150.0, 1.0),
        "least_trusted_seen": least_trusted_rank,
    }


def _sigmoid(x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0


def _local_score(features: dict[str, float]) -> float:
    weighted_sum = BIAS + sum(FEATURE_WEIGHTS[name] * value for name, value in features.items())
    return round(_sigmoid(weighted_sum), 4)


def _call_remote_monitor(url: str, request: DefenseRequest) -> float | None:
    """Best-effort call to a running instance of the ``learned-monitor``
    starter kit. Any failure (unreachable, timeout, bad response) falls back
    to the local heuristic -- a monitor that is down must never block the
    whole defense.

    Contract: the learned-monitor kit exposes ``POST /v1/decision`` and
    returns a full ``{"decision", "risk_score", "confidence", "reason_codes"}``
    object (see ``starter-kits/learned-monitor/monitor/model.py::decide``),
    not a bare score -- only ``risk_score`` is used here, since C4's job is
    to contribute one signal, not to make the final call itself."""
    try:
        response = httpx.post(
            url.rstrip("/") + "/v1/decision",
            json=request.model_dump(mode="json"),
            timeout=REMOTE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        score = float(payload["risk_score"])
        return max(0.0, min(1.0, score))
    except Exception:
        return None


def evaluate(
    action: CandidateAction,
    request: DefenseRequest,
    tagged: TaggedRequest,
    session: SessionState,
    authority: AuthorityResult,
    policy: PolicyResult,
    content: ContentResult,
) -> MonitorResult:
    features = _features(action, request, tagged, session, authority, policy, content)

    remote_url = os.environ.get(MONITOR_URL_ENV)
    if remote_url:
        remote_score = _call_remote_monitor(remote_url, request)
        if remote_score is not None:
            return MonitorResult(score=remote_score, source="remote")
        return MonitorResult(score=_local_score(features), source="local_heuristic_fallback")

    return MonitorResult(score=_local_score(features), source="local_heuristic")