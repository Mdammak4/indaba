"""Component C2: Deterministic policy — hard rules that never depend on scores.

C2 answers three questions using only ``request.policy_context`` and
``request.history_digest`` (both organizer-provided, never a scenario id or a
hard-coded expected outcome):

1. Is this tool allowed for the task at all?
2. If the tool is consequential, has a human actually confirmed *this exact*
   action already?
3. If the tool is the final step of a sequence (e.g. an "_execute" step),
   has the required earlier step of that sequence actually happened?

The three ``finance_standard.yaml`` / ``enterprise_standard.yaml`` /
``soc_standard.yaml`` policies all express the same three shapes
(``tool_permission``, ``requires_confirmation``, ``prerequisite``) with
different tool names per domain. Rather than hard-coding tool names, C2
detects the "final step of a sequence" pattern generically, from naming
convention (``payment_execute`` needs ``payment_confirm``;
``remediation_execute`` needs ``remediation_prepare``) and confirms the
prerequisite happened by reading the run's own history -- never a scenario
label.

``forbidden_effect`` rules are intentionally NOT implemented here: the
concrete forbidden effect for a scenario is an evaluator-only label. A
defense that tried to read it would be reasoning from a hard-coded expected
outcome, exactly what the spec disqualifies. C2 achieves the same protective
intent through the generic tool-permission and sequence checks instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models import CandidateAction, DefenseRequest

# Suffix pairs that express "the final step of a sequence requires this
# earlier step first". Checked by string suffix on the tool name, so it
# generalizes across domains without naming a specific tool.
SEQUENCE_FINAL_SUFFIXES = ("_execute", "_confirm", "_close", "_finalize")
SEQUENCE_PREREQUISITE_SUFFIXES = ("_confirm", "_prepare", "_review", "_approve")


@dataclass
class PolicyViolation:
    rule_id: str
    reason_code: str
    severity: str  # "critical" | "high" | "medium"
    detail: str = ""


@dataclass
class PolicyResult:
    """C2's verdict for one candidate action. ``decision`` is a recommendation,
    not final -- the aggregator in decision.py still applies priority across
    C1-C4, but a "block" from here is never downgraded."""

    decision: str  # "allow" | "block" | "escalate"
    violations: list[PolicyViolation] = field(default_factory=list)

    @property
    def reason_codes(self) -> list[str]:
        return [v.reason_code for v in self.violations]


def _tool_prefix_for_sequence(tool: str) -> tuple[str, str] | None:
    """If ``tool`` looks like the final step of a prepare/confirm -> execute
    sequence, return (prefix, matched_suffix). Otherwise None."""
    for suffix in SEQUENCE_FINAL_SUFFIXES:
        if tool.endswith(suffix):
            return tool[: -len(suffix)], suffix
    return None


def _prerequisite_satisfied(prefix: str, request: DefenseRequest) -> bool:
    """A prerequisite step for this run counts only if it was itself allowed
    (or was later confirmed) -- a blocked or escalated attempt does not
    satisfy the sequence."""
    for call in request.history_digest.tool_calls:
        tool = str(call.get("tool", ""))
        decision = str(call.get("decision", ""))
        succeeded = call.get("succeeded", True)
        if not tool.startswith(prefix):
            continue
        if any(tool.endswith(s) for s in SEQUENCE_PREREQUISITE_SUFFIXES):
            if decision == "allow" and succeeded is not False:
                return True
    return False


def _is_consequential(action: CandidateAction, policy_context: dict) -> bool:
    tool = action.tool or ""
    if tool in policy_context.get("consequential_tools", []):
        return True
    if tool in policy_context.get("confirmation_required_tools", []):
        return True
    return False


def evaluate(action: CandidateAction, request: DefenseRequest, action_digest: str) -> PolicyResult:
    """Run C2 against one candidate action. ``action`` is already resolved to
    the *target* action (i.e. ``confirmation_for`` when the candidate is a
    ``request_confirmation``) -- decision.py resolves this once and passes it
    to every component so C1-C4 all judge the same underlying action."""
    if action.type != "tool_call" or not action.tool:
        return PolicyResult(decision="allow")

    policy_context = request.policy_context
    violations: list[PolicyViolation] = []

    # 1. Tool permission -- the one rule present in every domain policy.
    allowed_tools = policy_context.get("allowed_tools", [])
    if allowed_tools and action.tool not in allowed_tools:
        violations.append(
            PolicyViolation(
                rule_id="TOOL_PERMISSION",
                reason_code="TOOL_NOT_ALLOWED",
                severity="high",
                detail=f"{action.tool!r} is not in this task's allowed_tools",
            )
        )
        # A tool outside the task's scope is a hard stop -- nothing else
        # about this action is worth evaluating.
        return PolicyResult(decision="block", violations=violations)

    # 2. Sequence prerequisite -- e.g. payment_execute needs a prior,
    # successful payment_confirm in *this* run.
    sequence = _tool_prefix_for_sequence(action.tool)
    if sequence is not None:
        prefix, _ = sequence
        if not _prerequisite_satisfied(prefix, request):
            violations.append(
                PolicyViolation(
                    rule_id="SEQUENCE_PREREQUISITE",
                    reason_code="PREREQUISITE_NOT_MET",
                    severity="high",
                    detail=f"{action.tool!r} requires an earlier confirmed/prepared step for {prefix!r}",
                )
            )
            return PolicyResult(decision="block", violations=violations)

    # 3. Confirmation requirement -- consequential actions need a recorded
    # human confirmation of this *exact* action (matched by its digest).
    if _is_consequential(action, policy_context):
        if action_digest not in request.history_digest.confirmations_granted:
            violations.append(
                PolicyViolation(
                    rule_id="REQUIRES_CONFIRMATION",
                    reason_code="MISSING_CONFIRMATION",
                    severity="critical",
                    detail=f"{action.tool!r} is consequential and has no recorded confirmation",
                )
            )
            return PolicyResult(decision="escalate", violations=violations)

    return PolicyResult(decision="allow", violations=violations)