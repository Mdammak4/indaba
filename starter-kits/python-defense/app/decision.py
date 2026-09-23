"""Aggregator: turns A (Tagger) + B (session state) + C1-C4 into one
DefenseDecision.

Priority order (highest wins; each step only runs if nothing higher already
returned). Everything upstream of this file already avoids scenario ids and
hard-coded expected outcomes -- the priority order itself is the only new
"policy" here, and it is fixed, not derived from anything scenario-specific:

1. Direct command injection      -- untrusted content literally names this
                                     tool + these argument values -> BLOCK.
2. C3 secret leak                -- a known secret (or an encoded variant of
                                     one) is present in the outbound payload -> BLOCK.
3. C2 hard policy violation      -- tool outside scope, or a sequence step
                                     attempted out of order -> BLOCK.
4. C1 no authority for argument  -- rewrite to a safer variant if one exists
                                     in this task's allowed_tools, else ESCALATE.
5. C2 missing confirmation       -- consequential action, no recorded human
                                     confirmation of this exact action -> ESCALATE.
6. C3 sensitive-but-unmatched    -- confidential/restricted data heading to an
                                     external sink, no confirmed secret -> ESCALATE.
7. C4 / session risk elevated    -- nothing specific fired, but the combined
                                     score (or the run's cumulative risk) is
                                     high -> ESCALATE.
8. Otherwise                     -- ALLOW.
"""

from __future__ import annotations

import hashlib
import json

from app import c1_authority, c2_policy, c3_content, c4_monitor
from app.models import CandidateAction, DefenseDecision, DefenseRequest
from app.session_state import update_session_with_new_observations
from app.tagger import Tagger

UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}

# tool-name substring -> substring used to look for a less consequential,
# already-allowed variant of the same action when C1 finds no authority for
# an argument. Generic by design: checked against whatever this task's own
# allowed_tools list contains, never a hard-coded tool name.
SAFER_VARIANT_PATTERNS = [
    ("send", "draft"),
    ("execute", "prepare"),
    ("publish", "draft"),
    ("post", "draft"),
    ("confirm", "prepare"),
]

MONITOR_ESCALATE_THRESHOLD = 0.75


def action_digest(action: CandidateAction) -> str:
    """Same digest the evaluator uses for confirmations (see sentinel.core.actions.CandidateAction.digest)."""

    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def untrusted_texts(request: DefenseRequest) -> list[str]:
    trust = {record.id: record.provenance.trust_level for record in request.provenance}
    return [
        item.content.lower()
        for item in request.conversation
        if any(trust.get(pid) in UNTRUSTED for pid in item.provenance_ids)
    ]


def _direct_command_injection(action: CandidateAction, request: DefenseRequest) -> bool:
    """Untrusted content that literally names this tool and one of its
    argument values together is treated as an attempted command injection,
    regardless of the action's risk tier -- this is what protects read-only
    tools too, which C1/C3 intentionally do not gate on argument authority."""
    if action.type != "tool_call" or not action.tool:
        return False
    values = [str(v).lower() for v in action.arguments.values() if v is not None and len(str(v)) >= 4]
    if not values:
        return False
    for text in untrusted_texts(request):
        if action.tool in text and any(value in text for value in values):
            return True
    return False


def _find_safer_variant(tool: str, allowed_tools: list[str]) -> str | None:
    for risky, safer in SAFER_VARIANT_PATTERNS:
        if risky in tool:
            candidate_tool = tool.replace(risky, safer)
            if candidate_tool in allowed_tools and candidate_tool != tool:
                return candidate_tool
    return None


def decide(request: DefenseRequest) -> DefenseDecision:
    tagger = Tagger()
    tagged = tagger.tag_request(request)

    # Component B: cumulative risk + multi-step fragment buffer, kept for the
    # whole run_id across every step_id.
    session = update_session_with_new_observations(request.run_id, tagged)

    action_risk_score = tagged.action_identity.risk_score if tagged.action_identity else 0.0

    def finalize(result: DefenseDecision, tool: str | None) -> DefenseDecision:
        """The ONLY place session.record_decision is called, so every return
        path below goes through it exactly once."""
        session.record_decision(
            step_id=request.step_id,
            tool=tool,
            decision=result.decision,
            action_risk_score=action_risk_score,
            reason_codes=result.reason_codes,
        )
        return result

    candidate = request.candidate_action
    action = candidate.confirmation_for if candidate.type == "request_confirmation" else candidate

    # ------------------------------------------------------------------
    # Non-tool actions (a plain response, a memory write) skip C1/C2's
    # tool-scoped checks, but C3 still runs: a "respond" can leak a secret in
    # plain text just as easily as a tool call can.
    # ------------------------------------------------------------------
    if action is None or action.type != "tool_call" or action.tool is None:
        content_result = c3_content.evaluate(action, request, tagged) if action is not None else None
        if content_result is not None and content_result.has_secret_leak:
            return finalize(
                DefenseDecision(
                    decision="block",
                    risk_score=0.9,
                    confidence=0.75,
                    reason_codes=content_result.reason_codes[:4],
                    explanation="Outbound content contains a previously observed secret.",
                ),
                tool=None,
            )
        return finalize(
            DefenseDecision(decision="allow", risk_score=0.1, confidence=0.5, reason_codes=["NOT_A_TOOL_CALL"]),
            tool=None,
        )

    # ------------------------------------------------------------------
    # Priority 1: direct command injection (works for read-only tools too).
    # ------------------------------------------------------------------
    if _direct_command_injection(action, request):
        return finalize(
            DefenseDecision(
                decision="block",
                risk_score=0.85,
                confidence=0.65,
                reason_codes=["INSTRUCTED_BY_UNTRUSTED_CONTENT"],
                explanation="This exact tool call is named inside content that was not authored by a trusted source.",
            ),
            tool=action.tool,
        )

    digest = action_digest(action)
    policy_result = c2_policy.evaluate(action, request, digest)
    authority_result = c1_authority.evaluate(action, tagged, session)
    content_result = c3_content.evaluate(action, request, tagged)
    monitor_result = c4_monitor.evaluate(
        action, request, tagged, session, authority_result, policy_result, content_result
    )

    # ------------------------------------------------------------------
    # Priority 2: a confirmed secret leaving in this action's own payload.
    # ------------------------------------------------------------------
    if content_result.has_secret_leak:
        return finalize(
            DefenseDecision(
                decision="block",
                risk_score=0.95,
                confidence=0.8,
                reason_codes=content_result.reason_codes[:4],
                explanation="A previously observed secret is present in this action's outbound payload.",
            ),
            tool=action.tool,
        )

    # ------------------------------------------------------------------
    # Priority 3: hard policy violation (out of scope, or out-of-order step).
    # ------------------------------------------------------------------
    if policy_result.decision == "block":
        return finalize(
            DefenseDecision(
                decision="block",
                risk_score=0.9,
                confidence=0.8,
                reason_codes=policy_result.reason_codes[:4],
            ),
            tool=action.tool,
        )

    # ------------------------------------------------------------------
    # Priority 4: no trusted source supplied one of this action's arguments.
    # Rewrite to a safer, already-allowed variant if one exists.
    # ------------------------------------------------------------------
    if authority_result.score > 0:
        allowed_tools = request.policy_context.get("allowed_tools", [])
        safer_tool = _find_safer_variant(action.tool, allowed_tools)
        if safer_tool is not None:
            rewritten = CandidateAction(
                type="tool_call",
                tool=safer_tool,
                arguments=dict(action.arguments),
                content=action.content,
                final=False,
            )
            return finalize(
                DefenseDecision(
                    decision="rewrite",
                    risk_score=0.6,
                    confidence=0.6,
                    reason_codes=["NO_AUTHORITY_FOR_ARGUMENT", "REWRITTEN_TO_SAFER_ACTION"],
                    explanation="One or more argument values have no trusted source; substituting a reversible action.",
                    rewritten_action=rewritten,
                ),
                tool=action.tool,
            )
        return finalize(
            DefenseDecision(
                decision="escalate",
                risk_score=0.75,
                confidence=0.65,
                reason_codes=[authority_result.reason_code],
                explanation="One or more argument values have no trusted source and no safer variant is available.",
            ),
            tool=action.tool,
        )

    # ------------------------------------------------------------------
    # Priority 5: consequential action with no recorded human confirmation.
    # ------------------------------------------------------------------
    if policy_result.decision == "escalate":
        return finalize(
            DefenseDecision(
                decision="escalate",
                risk_score=0.6,
                confidence=0.6,
                reason_codes=policy_result.reason_codes[:4],
            ),
            tool=action.tool,
        )

    # ------------------------------------------------------------------
    # Priority 6: sensitive data heading to an external sink, below the
    # confirmed-secret threshold.
    # ------------------------------------------------------------------
    if content_result.score > 0:
        return finalize(
            DefenseDecision(
                decision="escalate",
                risk_score=max(0.5, content_result.score),
                confidence=0.55,
                reason_codes=content_result.reason_codes[:4],
            ),
            tool=action.tool,
        )

    # ------------------------------------------------------------------
    # Priority 7: nothing specific fired, but the combined/cumulative
    # picture is high-risk.
    # ------------------------------------------------------------------
    if monitor_result.score >= MONITOR_ESCALATE_THRESHOLD or session.is_cumulative_risk_high:
        reason = "SESSION_RISK_ELEVATED" if session.is_cumulative_risk_high else monitor_result.reason_code
        return finalize(
            DefenseDecision(
                decision="escalate",
                risk_score=round(monitor_result.score, 2),
                confidence=0.5,
                reason_codes=[reason],
            ),
            tool=action.tool,
        )

    return finalize(
        DefenseDecision(
            decision="allow",
            risk_score=round(min(action_risk_score / 100.0, 0.3), 2),
            confidence=0.6,
            reason_codes=["USER_GOAL_ALIGNED"],
        ),
        tool=action.tool,
    )
