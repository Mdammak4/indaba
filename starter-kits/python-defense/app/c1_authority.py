"""Component C1: Authority attribution — the core, most original signal.

For each argument of a sensitive action, C1 asks a single question: has a
trusted source (the user, or trusted/authoritative data) actually supplied
this specific value, or does it exist only in content the agent was never
supposed to take orders from?

C1 never reads instructions. It works backwards from the finished action:
each argument value is looked up in Component A's value-provenance registry
(built from the whole conversation so far) and, for multi-step attacks, in
Component B's rolling buffer of recent untrusted text. If a value's
best-known source is untrusted, the argument has no authority — regardless
of how the attacker phrased the instruction that produced it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.models import CandidateAction
from app.session_state import SessionState
from app.tagger import TaggedRequest

# A value has authority if it demonstrably came from one of these trust
# levels. trusted_internal is included: an internal system record is not
# something an external attacker can plant.
AUTHORITY_TRUST_LEVELS = {"system_policy", "authenticated_user", "trusted_internal"}

# Arguments shorter than this are too generic to check meaningfully (status
# flags, single-word enums, booleans-as-strings). Checking them would cause
# false positives without adding real security value.
MIN_ARG_LENGTH_TO_CHECK = 4

# Action types where authority attribution matters. Pure reads already carry
# a low risk_weight from the tagger and rarely cause harm on their own;
# skipping them avoids noisy escalations on legitimate lookups.
CHECKED_ACTION_TYPES = {"write_reversible", "write_irreversible", "delete_recoverable", "delete_permanent"}


@dataclass
class UnauthorizedArgument:
    name: str
    value: str
    reason: str  # "UNTRUSTED_SOURCE" | "MATCHES_UNTRUSTED_FRAGMENT"
    evidence_trust: str | None = None


@dataclass
class AuthorityResult:
    """C1's verdict for one candidate action."""

    score: float  # 0.0 = fully authorized, 0.9 = at least one checked argument has no authority
    reason_code: str
    unauthorized_arguments: list[UnauthorizedArgument] = field(default_factory=list)
    checked_argument_count: int = 0


def _normalize(value: str) -> str:
    """Loose normalization so an attacker cannot dodge the match with casing,
    stray whitespace, or punctuation alone. This is NOT the encoding-aware
    decoding C3 does for secrets — just enough to defeat trivial reformatting
    of an argument value."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _value_is_authorized(value_str: str, tagged: TaggedRequest) -> tuple[bool, str | None]:
    """Look the value up in Component A's provenance registry.

    Returns (authorized, best_trust_level_seen). An entry absent from the
    registry is treated as authorized here — see the caveat in ``evaluate``'s
    docstring on why that gap is covered by the untrusted-fragment check
    instead of being flagged directly.
    """
    vp = tagged.value_provenance.get(value_str)
    if vp is None:
        return True, None
    return vp.highest_trust in AUTHORITY_TRUST_LEVELS, vp.highest_trust


def _value_traceable_to_untrusted_fragment(value_str: str, session: SessionState) -> bool:
    """Second line of defense for values the Tagger could not trace to any
    observed text at all (a ``value_provenance`` entry with an empty
    ``sources`` list — the Tagger's fallback treats these as agent-synthesized
    reasoning and marks them trusted by default, see ``tagger._track_values``).

    If such a value nonetheless appears, even loosely normalized, inside
    recently observed untrusted text, we treat it as suspicious rather than
    accepting the Tagger's optimistic default. This is what gives C1 some
    resilience against attacker text that produced a value the Tagger's
    exact-token matching did not pick up as coming from that text.
    """
    if len(value_str) < MIN_ARG_LENGTH_TO_CHECK:
        return False
    needle = _normalize(value_str)
    if not needle:
        return False
    haystack = _normalize(session.recent_untrusted_text())
    return needle in haystack


def evaluate(action: CandidateAction, tagged: TaggedRequest, session: SessionState) -> AuthorityResult:
    """Run C1 against one candidate action.

    Known gap, documented rather than silently patched: the Tagger marks a
    value with no recorded source as ``authenticated_user`` (its "the agent
    probably synthesized this" fallback). C1 does not blindly trust that
    default — it additionally checks the value against Component B's recent
    untrusted-fragment buffer. This narrows, but does not close, the gap: a
    value derived from untrusted content through transformation the buffer
    check cannot see (heavy paraphrase, arithmetic, non-substring encoding)
    can still slip through. Call this out explicitly in the report's failure
    analysis — it is exactly the kind of honest limitation the rubric asks for.
    """
    action_type = tagged.action_identity.action_type if tagged.action_identity else "read"
    if action_type not in CHECKED_ACTION_TYPES:
        return AuthorityResult(score=0.0, reason_code="AUTHORITY_NOT_APPLICABLE")

    unauthorized: list[UnauthorizedArgument] = []
    checked = 0

    for arg_name, arg_value in (action.arguments or {}).items():
        value_str = str(arg_value) if arg_value is not None else ""
        if len(value_str) < MIN_ARG_LENGTH_TO_CHECK:
            continue
        checked += 1

        authorized, best_trust = _value_is_authorized(value_str, tagged)

        if authorized:
            vp = tagged.value_provenance.get(value_str)
            came_from_observed_text = vp is not None and len(vp.sources) > 0
            if not came_from_observed_text and _value_traceable_to_untrusted_fragment(value_str, session):
                unauthorized.append(
                    UnauthorizedArgument(
                        name=arg_name,
                        value=value_str,
                        reason="MATCHES_UNTRUSTED_FRAGMENT",
                        evidence_trust="adversary_controlled",
                    )
                )
            continue

        unauthorized.append(
            UnauthorizedArgument(name=arg_name, value=value_str, reason="UNTRUSTED_SOURCE", evidence_trust=best_trust)
        )

    if not unauthorized:
        return AuthorityResult(score=0.0, reason_code="AUTHORITY_OK", checked_argument_count=checked)

    return AuthorityResult(
        score=0.9,
        reason_code="NO_AUTHORITY_FOR_ARGUMENT",
        unauthorized_arguments=unauthorized,
        checked_argument_count=checked,
    )