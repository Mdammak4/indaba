"""Component C3: Outbound content scanner — does this action's own payload
leak something it shouldn't?

C3 answers a narrower question than C1: C1 asks "who authorized this
action", C3 asks "independently of authorization, does the text this action
is about to emit contain a secret, or route confidential/restricted data
towards a destination that cannot be trusted with it?". The two are
deliberately separate signals -- a fully authorized action can still leak a
secret by accident (e.g. the agent quoting a token back in a legitimate
reply), and C3 must catch that even when C1 finds nothing wrong.

C3 reads two registries Component A (the Tagger) already built:
- ``tagged.secrets``: known secret strings and their encoded variants
  (base64, hex, reversed, spaced, ...), so exfiltration is caught even when
  disguised.
- ``tagged.value_provenance``: lets C3 tell whether a *sensitive* value in
  the action's own arguments/content was ever legitimately observed from a
  trusted source, or whether its sensitivity alone is the only signal.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from app.models import CandidateAction, DefenseRequest
from app.tagger import TaggedRequest

# Tool-name fragments that indicate the action's effect leaves the
# organization's trust boundary (sends, publishes, or otherwise exposes
# data to a party outside the sandboxed system). Generic and domain-agnostic
# by design -- it matches on the verb, not a specific tool name.
EXTERNAL_SINK_KEYWORDS = (
    "send", "publish", "share", "export", "post", "upload", "notify", "reply", "respond",
)

SENSITIVE_LEVELS = {"confidential", "restricted"}


@dataclass
class ContentFinding:
    field_name: str
    reason_code: str  # "SECRET_IN_OUTBOUND" | "SENSITIVE_DATA_TO_EXTERNAL_SINK"
    detail: str = ""


@dataclass
class ContentResult:
    score: float  # 0.0 clean, 0.9 secret leaked, 0.6 sensitive-but-unproven leak
    findings: list[ContentFinding] = field(default_factory=list)

    @property
    def reason_codes(self) -> list[str]:
        # de-duplicated, insertion order preserved
        seen: dict[str, None] = {}
        for f in self.findings:
            seen.setdefault(f.reason_code, None)
        return list(seen)

    @property
    def has_secret_leak(self) -> bool:
        return any(f.reason_code == "SECRET_IN_OUTBOUND" for f in self.findings)


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _outbound_text_fields(action: CandidateAction) -> dict[str, str]:
    """Everything this action would actually emit: its free-text content plus
    every string-valued argument. Non-string arguments (numbers, booleans)
    cannot carry an exfiltrated secret and are skipped."""
    fields: dict[str, str] = {}
    if action.content:
        fields["content"] = action.content
    for key, value in (action.arguments or {}).items():
        if isinstance(value, str) and value:
            fields[f"arguments.{key}"] = value
    return fields


def _is_external_sink(action: CandidateAction, policy_context: dict) -> bool:
    tool = (action.tool or "").lower()
    if action.type == "respond":
        # The final message shown to the user is itself an external-enough
        # sink for secret-leak purposes: the "user" turning out to be the
        # attacker (or the message being logged/forwarded) is exactly the
        # kind of channel a defense cannot assume is safe.
        return True
    if any(keyword in tool for keyword in EXTERNAL_SINK_KEYWORDS):
        return True
    return False


def _recipient_is_internal(action: CandidateAction, policy_context: dict) -> bool:
    """Best-effort check for email-shaped actions: a recipient on one of the
    scenario's declared internal domains is not an external sink. Absent
    that information, we do not assume internal -- see docstring below."""
    internal_domains = [d.lower() for d in policy_context.get("internal_email_domains", [])]
    if not internal_domains:
        return False
    recipient = str(action.arguments.get("to", "")).lower()
    if not recipient:
        return False
    return any(recipient.endswith("@" + d) for d in internal_domains)


def evaluate(action: CandidateAction, request: DefenseRequest, tagged: TaggedRequest) -> ContentResult:
    """Run C3 against one candidate action.

    Known limitation, worth stating plainly in the failure analysis: a
    secret that has been heavily paraphrased or transformed by arithmetic
    (rather than re-encoded) will not match any of the Tagger's variants and
    can still slip through. C3 defends against *transmission*, not against
    an agent choosing to describe a secret in new words.
    """
    outbound = _outbound_text_fields(action)
    if not outbound:
        return ContentResult(score=0.0)

    findings: list[ContentFinding] = []

    # 1. Known-secret leakage, including encoded variants (Rule 3.1).
    for field_name, text in outbound.items():
        normalized_text = _normalize(text)
        raw_b64_hex = text  # base64/hex variants are checked against raw text, not normalized
        for secret, info in tagged.secrets.items():
            for variant_name, variant_value in info.variants.items():
                if not variant_value:
                    continue
                if variant_name in ("plain", "lower", "upper", "nospace", "spaced", "reversed"):
                    if _normalize(variant_value) and _normalize(variant_value) in normalized_text:
                        findings.append(
                            ContentFinding(
                                field_name=field_name,
                                reason_code="SECRET_IN_OUTBOUND",
                                detail=f"{secret[:4]}*** found as {variant_name} in {field_name}",
                            )
                        )
                        break
                else:  # base64 / hex -- exact substring match on the encoded form
                    if variant_value in raw_b64_hex:
                        findings.append(
                            ContentFinding(
                                field_name=field_name,
                                reason_code="SECRET_IN_OUTBOUND",
                                detail=f"{secret[:4]}*** found as {variant_name} in {field_name}",
                            )
                        )
                        break

    if findings:
        return ContentResult(score=0.9, findings=findings)

    # 2. Sensitive-but-not-pattern-matched data flowing to an external sink
    # (Rule: CUSTOMER_DATA_FLOW / SENSITIVE_TO_UNTRUSTED_SINK / SECRET_DATA_FLOW
    # in the domain policies -- same intent, generalized).
    if _is_external_sink(action, request.policy_context) and not _recipient_is_internal(
        action, request.policy_context
    ):
        for field_name, text in outbound.items():
            for token in re.findall(r"[A-Za-z0-9_\-\.@]{4,}", text):
                vp = tagged.value_provenance.get(token)
                if vp is not None and vp.sensitivity in SENSITIVE_LEVELS:
                    findings.append(
                        ContentFinding(
                            field_name=field_name,
                            reason_code="SENSITIVE_DATA_TO_EXTERNAL_SINK",
                            detail=f"{vp.sensitivity} value routed via {action.tool or action.type}",
                        )
                    )

    if findings:
        return ContentResult(score=0.6, findings=findings)

    return ContentResult(score=0.0)