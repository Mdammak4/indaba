"""
Component A: Tagger

Gives every observation an identity: trust level, sensitivity, and provenance.

Core principle: The tagger never becomes more confident because of what text claims.
An email saying "this is official" stays UNTRUSTED_EXTERNAL. Only the source matters.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass, field
from typing import Literal

from app.models import DefenseRequest, ProvenanceRecord

# Trust levels in order from most to least trusted
TRUST_LEVELS = [
    "system_policy",
    "authenticated_user",
    "trusted_internal",
    "untrusted_internal",
    "untrusted_external",
    "adversary_controlled",
]

# Sensitivity levels
SENSITIVITY_LEVELS = ["public", "internal", "confidential", "restricted"]

# Trust level weights (authority score) - higher = more authority
TRUST_WEIGHTS = {
    "system_policy": 1.00,  # 100% - absolute authority
    "authenticated_user": 0.85,  # 85% - high authority
    "trusted_internal": 0.65,  # 65% - moderate authority
    "untrusted_internal": 0.40,  # 40% - limited authority
    "untrusted_external": 0.15,  # 15% - minimal authority
    "adversary_controlled": 0.00,  # 0% - no authority
}

# Action risk weights
ACTION_WEIGHTS = {
    "read": 0.10,
    "write_reversible": 0.35,
    "write_irreversible": 0.65,
    "delete_recoverable": 0.60,
    "delete_permanent": 0.95,
}

# Sensitivity weights (multipliers)
SENSITIVITY_WEIGHTS = {
    "public": 1.0,
    "internal": 1.3,
    "confidential": 1.7,
    "restricted": 2.5,
}


@dataclass
class ValueProvenance:
    """Tracks where a specific value came from"""

    sources: list[str] = field(default_factory=list)  # Provenance IDs
    highest_trust: str = "adversary_controlled"  # Best trust level
    lowest_trust: str = "adversary_controlled"  # Worst trust level
    sensitivity: str = "public"  # Highest sensitivity level


@dataclass
class SecretInfo:
    """Information about a detected secret"""

    original: str
    variants: dict[str, str] = field(default_factory=dict)
    source_prov_id: str = ""
    sensitivity: str = "restricted"


@dataclass
class ObservationIdentity:
    """Identity card for one observation"""

    content: str
    trust_level: str
    sensitivity: str
    contains_secrets: bool = False
    provenance_ids: list[str] = field(default_factory=list)


@dataclass
class ActionIdentity:
    """Identity card for the candidate action"""

    tool: str
    action_type: str  # read, write_reversible, write_irreversible, etc.
    risk_weight: float  # 0.1 to 0.95
    is_reversible: bool
    requires_confirmation: bool
    arguments: dict = field(default_factory=dict)
    risk_score: float = 0.0  # Calculated: 0-100
    risk_level: str = "UNKNOWN"  # SAFE, LOW, MODERATE, HIGH, CRITICAL


@dataclass
class TaggedRequest:
    """Enriched request with all identities and registries"""

    # Provenance lookup: prov_id → trust + sensitivity
    provenance_map: dict[str, dict] = field(default_factory=dict)

    # Value registry: value → where it came from
    value_provenance: dict[str, ValueProvenance] = field(default_factory=dict)

    # Secret registry: secret → variants
    secrets: dict[str, SecretInfo] = field(default_factory=dict)

    # Observation identities
    observations: list[ObservationIdentity] = field(default_factory=list)

    # Memory trust tracking
    memory_trust: dict[str, str] = field(default_factory=dict)

    # Action identity (NEW)
    action_identity: ActionIdentity | None = None


class Tagger:
    """
    Component A: Tag observations with trust and sensitivity.

    Implements the four rules from the architecture:
    1. Take simulator label when it exists
    2. Split tool results field-by-field
    3. Memory inherits lowest trust level read
    4. When in doubt, take lowest level
    """

    def __init__(self):
        # Secret detection patterns
        self.secret_patterns = [
            r"token[=:]\s*([A-Za-z0-9_\-]{10,})",
            r"password[=:]\s*([A-Za-z0-9_\-!@#$%^&*]{6,})",
            r"api[_-]?key[=:]\s*([A-Za-z0-9_\-]{20,})",
            r"bearer\s+([A-Za-z0-9_\-\.]{20,})",
            r"sk-[A-Za-z0-9]{32,}",  # API key pattern
            r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}",  # IBAN-like
            r"[A-Z0-9]{2,}-[A-F0-9]{4,}",  # Token pattern like PORTAL-9F2A
        ]

        # Entropy threshold for random strings
        self.entropy_threshold = 4.5

        # Field-level trust mapping for tool results
        self.trusted_fields = {
            "status",
            "id",
            "timestamp",
            "created_at",
            "updated_at",
            "payment_id",
            "alert_id",
            "incident_id",
            "ticket_id",
        }

        self.untrusted_fields = {
            "note",
            "comment",
            "description",
            "summary",
            "body",
            "message",
            "text",
        }

    def tag_request(self, request: DefenseRequest) -> TaggedRequest:
        """
        Main entry point: process entire request and create enriched data.

        Args:
            request: The defense request from SENTINEL

        Returns:
            TaggedRequest with all identities and registries
        """
        tagged = TaggedRequest()

        # 1. Build provenance map from simulator data
        tagged.provenance_map = self._build_provenance_map(request)

        # 2. Process conversation and track values
        tagged.observations = self._tag_observations(request, tagged.provenance_map)

        # 3. Track where each value came from
        tagged.value_provenance = self._track_values(request, tagged.provenance_map)

        # 4. Detect secrets in content
        tagged.secrets = self._detect_secrets(request, tagged.provenance_map)

        # 5. Track memory trust inheritance
        tagged.memory_trust = self._track_memory_trust(request, tagged.provenance_map)

        # 6. Classify the action (NEW)
        tagged.action_identity = self._classify_action(request.candidate_action, tagged.value_provenance)

        return tagged

    def _build_provenance_map(self, request: DefenseRequest) -> dict[str, dict]:
        """
        Extract provenance information from the request.

        Rule 1: Take simulator label when it exists.
        """
        prov_map = {}

        for record in request.provenance:
            prov_map[record.id] = {
                "trust_level": record.provenance.trust_level,
                "sensitivity": record.provenance.sensitivity,
                "source_type": record.provenance.source_type,
                "source_id": record.provenance.source_id,
                "origin_actor": record.provenance.origin_actor,
                "retrieved_via": record.provenance.retrieved_via,
            }

        return prov_map

    def _tag_observations(
        self, request: DefenseRequest, provenance_map: dict
    ) -> list[ObservationIdentity]:
        """
        Create identity cards for each observation in the conversation.

        Rule 2: Split tool results field-by-field when possible.
        """
        observations = []

        for item in request.conversation:
            # Get trust and sensitivity from provenance
            if not item.provenance_ids:
                # No provenance = lowest trust (Rule 4)
                trust = "adversary_controlled"
                sensitivity = "public"
            else:
                # Get lowest trust from all provenance IDs (Rule 3)
                trust_levels = []
                sensitivities = []

                for prov_id in item.provenance_ids:
                    if prov_id in provenance_map:
                        trust_levels.append(provenance_map[prov_id]["trust_level"])
                        sensitivities.append(provenance_map[prov_id]["sensitivity"])

                trust = self._get_lowest_trust(trust_levels) if trust_levels else "adversary_controlled"
                sensitivity = self._get_highest_sensitivity(sensitivities) if sensitivities else "public"

            # Check if content contains secrets
            contains_secrets = self._content_has_secrets(item.content)

            observation = ObservationIdentity(
                content=item.content,
                trust_level=trust,
                sensitivity=sensitivity,
                contains_secrets=contains_secrets,
                provenance_ids=item.provenance_ids,
            )

            observations.append(observation)

        return observations

    def _track_values(self, request: DefenseRequest, provenance_map: dict) -> dict[str, ValueProvenance]:
        """
        Build registry: value → where it came from.

        This is what C1 (Authority) uses to check if a value has authority.
        """
        value_registry = {}

        # Track values from conversation
        for item in request.conversation:
            # Extract potential values (simple tokenization)
            tokens = self._extract_tokens(item.content)

            for token in tokens:
                if token not in value_registry:
                    value_registry[token] = ValueProvenance()

                # Add source provenance IDs
                value_registry[token].sources.extend(item.provenance_ids)

                # Update trust levels
                for prov_id in item.provenance_ids:
                    if prov_id in provenance_map:
                        prov = provenance_map[prov_id]
                        current_trust = prov["trust_level"]

                        # Update highest trust (most trusted)
                        if self._trust_level_value(current_trust) > self._trust_level_value(
                            value_registry[token].highest_trust
                        ):
                            value_registry[token].highest_trust = current_trust

                        # Update lowest trust (least trusted)
                        if self._trust_level_value(current_trust) < self._trust_level_value(
                            value_registry[token].lowest_trust
                        ):
                            value_registry[token].lowest_trust = current_trust

                        # Update sensitivity (take highest)
                        if self._sensitivity_level_value(prov["sensitivity"]) > self._sensitivity_level_value(
                            value_registry[token].sensitivity
                        ):
                            value_registry[token].sensitivity = prov["sensitivity"]

        # Also track values from action arguments
        if request.candidate_action.arguments:
            for key, value in request.candidate_action.arguments.items():
                value_str = str(value)
                if value_str and value_str not in value_registry:
                    # If we haven't seen this value, it might be synthesized by the agent
                    value_registry[value_str] = ValueProvenance(
                        sources=[],
                        highest_trust="authenticated_user",  # Agent reasoning
                        lowest_trust="authenticated_user",
                    )

        return value_registry

    def _detect_secrets(self, request: DefenseRequest, provenance_map: dict) -> dict[str, SecretInfo]:
        """
        Detect secrets using patterns + entropy, with encoded variants.

        This builds the registry that C3 (Content Scanner) uses.
        """
        secrets = {}

        for item in request.conversation:
            # 1. Pattern-based detection
            for pattern in self.secret_patterns:
                matches = re.findall(pattern, item.content, re.IGNORECASE)
                for match in matches:
                    if match and len(match) >= 8:  # Minimum length
                        secrets[match] = self._create_secret_info(match, item.provenance_ids, provenance_map)

            # 2. Entropy-based detection (high-entropy strings)
            tokens = self._extract_tokens(item.content)
            for token in tokens:
                if len(token) >= 12 and self._calculate_entropy(token) > self.entropy_threshold:
                    if token not in secrets:
                        secrets[token] = self._create_secret_info(token, item.provenance_ids, provenance_map)

        return secrets

    def _create_secret_info(
        self, secret: str, provenance_ids: list[str], provenance_map: dict
    ) -> SecretInfo:
        """Create secret info with encoded variants"""
        variants = self._generate_secret_variants(secret)

        # Get sensitivity from provenance
        sensitivity = "restricted"
        source_prov_id = provenance_ids[0] if provenance_ids else ""

        if source_prov_id and source_prov_id in provenance_map:
            sensitivity = provenance_map[source_prov_id]["sensitivity"]

        return SecretInfo(
            original=secret,
            variants=variants,
            source_prov_id=source_prov_id,
            sensitivity=sensitivity,
        )

    def _generate_secret_variants(self, secret: str) -> dict[str, str]:
        """
        Generate encoded variants of a secret for C3 to match against.

        These are the common exfiltration encodings mentioned in the spec.
        """
        variants = {}

        # Plain variants
        variants["plain"] = secret
        variants["lower"] = secret.lower()
        variants["upper"] = secret.upper()
        variants["nospace"] = secret.replace(" ", "")

        # Base64
        try:
            variants["base64"] = base64.b64encode(secret.encode()).decode()
        except Exception:
            pass

        # Hex
        try:
            variants["hex"] = secret.encode().hex()
        except Exception:
            pass

        # Reversed
        variants["reversed"] = secret[::-1]

        # Spaced (each character separated by space)
        variants["spaced"] = " ".join(secret)

        return variants

    def _track_memory_trust(self, request: DefenseRequest, provenance_map: dict) -> dict[str, str]:
        """
        Rule 3: Memory inherits the lowest trust level from what was read.

        If the agent writes a memory after reading untrusted text,
        that memory stays untrusted when recalled later.
        """
        memory_trust = {}

        # Track memory writes in conversation
        for item in request.conversation:
            if "memory" in item.kind.lower() or "MEM-" in item.content:
                # Extract memory ID
                mem_match = re.search(r"MEM-\d+", item.content)
                if mem_match:
                    mem_id = mem_match.group(0)

                    # Get lowest trust from provenance
                    trust_levels = []
                    for prov_id in item.provenance_ids:
                        if prov_id in provenance_map:
                            trust_levels.append(provenance_map[prov_id]["trust_level"])

                    if trust_levels:
                        memory_trust[mem_id] = self._get_lowest_trust(trust_levels)

        return memory_trust

    # Helper methods

    def _extract_tokens(self, content: str) -> list[str]:
        """Extract potential values from content (simple tokenization)"""
        # Split on whitespace and common delimiters
        tokens = re.findall(r"[A-Za-z0-9_\-\.@]+", content)
        # Filter: keep tokens that look like values (not common words)
        return [t for t in tokens if len(t) >= 4 and not t.lower() in {"this", "that", "with", "from", "have"}]

    def _content_has_secrets(self, content: str) -> bool:
        """Quick check if content likely contains secrets"""
        for pattern in self.secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0.0
        prob = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def _trust_level_value(self, trust_level: str) -> int:
        """Convert trust level to numeric value (higher = more trusted)"""
        try:
            return len(TRUST_LEVELS) - TRUST_LEVELS.index(trust_level)
        except ValueError:
            return 0

    def _sensitivity_level_value(self, sensitivity: str) -> int:
        """Convert sensitivity to numeric value (higher = more sensitive)"""
        try:
            return SENSITIVITY_LEVELS.index(sensitivity)
        except ValueError:
            return 0

    def _get_lowest_trust(self, trust_levels: list[str]) -> str:
        """Get the least trusted level from a list (Rule 3, 4)"""
        if not trust_levels:
            return "adversary_controlled"

        lowest = trust_levels[0]
        for trust in trust_levels:
            if self._trust_level_value(trust) < self._trust_level_value(lowest):
                lowest = trust

        return lowest

    def _get_highest_sensitivity(self, sensitivities: list[str]) -> str:
        """Get the most sensitive level from a list"""
        if not sensitivities:
            return "public"

        highest = sensitivities[0]
        for sens in sensitivities:
            if self._sensitivity_level_value(sens) > self._sensitivity_level_value(highest):
                highest = sens

        return highest

    def _classify_action(
        self, action: CandidateAction, value_provenance: dict[str, ValueProvenance]
    ) -> ActionIdentity:
        """
        Classify action by type and calculate risk score.

        Uses the weighted scoring system:
        - Trust level weight (0.0-1.0)
        - Action risk weight (0.1-0.95)
        - Sensitivity multiplier (1.0-2.5)
        """
        from app.models import CandidateAction

        tool = action.tool or ""
        arguments = action.arguments or {}

        # Classify action type
        action_type, risk_weight, is_reversible = self._classify_action_type(tool, arguments)

        # Check if confirmation is needed
        requires_confirmation = risk_weight >= 0.6  # High-risk actions

        # Calculate risk score based on argument values
        risk_score, risk_level = self._calculate_action_risk_score(
            action_type, risk_weight, arguments, value_provenance
        )

        return ActionIdentity(
            tool=tool,
            action_type=action_type,
            risk_weight=risk_weight,
            is_reversible=is_reversible,
            requires_confirmation=requires_confirmation,
            arguments=arguments,
            risk_score=risk_score,
            risk_level=risk_level,
        )

    def _classify_action_type(self, tool: str, arguments: dict) -> tuple[str, float, bool]:
        """
        Classify action type and return (type, risk_weight, is_reversible).

        Action types:
        - read: 0.10
        - write_reversible: 0.35
        - write_irreversible: 0.65
        - delete_recoverable: 0.60
        - delete_permanent: 0.95
        """
        tool_lower = tool.lower()

        # Read operations (lowest risk)
        if any(op in tool_lower for op in ["read", "lookup", "search", "get", "list", "view"]):
            return ("read", 0.10, True)

        # Delete operations
        if any(op in tool_lower for op in ["delete", "remove", "purge"]):
            # Check if it's critical infrastructure
            if any(crit in tool_lower for crit in ["monitoring", "backup", "log", "security", "audit"]):
                return ("delete_permanent", 0.95, False)
            return ("delete_recoverable", 0.60, True)

        # Check status changes (closure is irreversible)
        status = str(arguments.get("status", "")).lower()
        if status in ["closed", "resolved", "completed", "archived"]:
            return ("write_irreversible", 0.65, False)

        # Write operations - distinguish reversible from irreversible
        reversible_keywords = ["draft", "prepare", "note", "memory", "save", "create"]
        irreversible_keywords = ["send", "execute", "confirm", "publish", "submit", "finalize", "close"]

        if any(op in tool_lower for op in reversible_keywords):
            return ("write_reversible", 0.35, True)

        if any(op in tool_lower for op in irreversible_keywords):
            return ("write_irreversible", 0.65, False)

        # Special cases
        if "disable" in tool_lower or "shutdown" in tool_lower:
            return ("delete_permanent", 0.95, False)

        if "update" in tool_lower:
            # Updates are usually irreversible
            return ("write_irreversible", 0.65, False)

        # Default: medium-risk write
        return ("write_reversible", 0.35, True)

    def _calculate_action_risk_score(
        self,
        action_type: str,
        action_weight: float,
        arguments: dict,
        value_provenance: dict[str, ValueProvenance],
    ) -> tuple[float, str]:
        """
        Calculate final risk score (0-100) based on action + data trust + sensitivity.

        Formula:
        RISK = (1 - trust_weight) × action_weight × sensitivity_weight × 100

        Classification:
        0-15: SAFE
        16-35: LOW
        36-55: MODERATE
        56-75: HIGH
        76-100: CRITICAL
        """
        # Find the lowest trust and highest sensitivity in action arguments
        lowest_trust_weight = 1.0  # Start with maximum trust
        highest_sensitivity_weight = 1.0  # Start with minimal sensitivity

        for key, value in arguments.items():
            value_str = str(value)

            # Look up this value in provenance
            if value_str in value_provenance:
                vp = value_provenance[value_str]

                # Get trust weight
                trust_weight = TRUST_WEIGHTS.get(vp.lowest_trust, 0.0)
                if trust_weight < lowest_trust_weight:
                    lowest_trust_weight = trust_weight

                # Get sensitivity weight
                sens_weight = SENSITIVITY_WEIGHTS.get(vp.sensitivity, 1.0)
                if sens_weight > highest_sensitivity_weight:
                    highest_sensitivity_weight = sens_weight

        # Calculate risk score
        risk = (1 - lowest_trust_weight) * action_weight * highest_sensitivity_weight

        # Convert to 0-100 scale
        score = min(risk * 100, 100)

        # Classify
        if score <= 15:
            level = "SAFE"
        elif score <= 35:
            level = "LOW"
        elif score <= 55:
            level = "MODERATE"
        elif score <= 75:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return (score, level)

    def calculate_risk_score(self, trust_level: str, action_type: str, sensitivity: str) -> tuple[float, str]:
        """
        Public utility method: calculate risk score for any combination.

        Args:
            trust_level: One of the 6 trust levels
            action_type: One of the 5 action types
            sensitivity: One of the 4 sensitivity levels

        Returns:
            (score, risk_level) where score is 0-100 and level is SAFE/LOW/MODERATE/HIGH/CRITICAL
        """
        trust_weight = TRUST_WEIGHTS.get(trust_level, 0.0)
        action_weight = ACTION_WEIGHTS.get(action_type, 0.5)
        sensitivity_weight = SENSITIVITY_WEIGHTS.get(sensitivity, 1.0)

        # Calculate risk
        risk = (1 - trust_weight) * action_weight * sensitivity_weight

        # Convert to 0-100 scale
        score = min(risk * 100, 100)

        # Classify
        if score <= 15:
            level = "SAFE"
        elif score <= 35:
            level = "LOW"
        elif score <= 55:
            level = "MODERATE"
        elif score <= 75:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return (score, level)
