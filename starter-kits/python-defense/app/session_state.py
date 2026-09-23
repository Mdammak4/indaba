"""Component B: Session State — the defense's own memory across a run.

The simulator already gives you ``request.history_digest`` per step (steps_taken,
blocked_count, escalated_count, least_trusted_seen, most_sensitive_seen). This
module does NOT duplicate that. It adds the two things the simulator does not
track for you:

1. A continuous cumulative risk score across the whole run (not just counts),
   so several individually-borderline actions can push the run into a higher
   alert state even if no single action crosses a hard threshold. This is what
   supports difficulty levels 4 (adaptive) and 5 (long horizon).

2. A rolling buffer of recent untrusted text, so an instruction an attacker
   split across several records (the simulator's "[part k/n]" directive
   grammar, see docs/scenario-authoring.md) can still be reconstructed and
   matched as a whole, even though each individual fragment looks harmless.

This module is intentionally storage-only: it never decides anything by
itself. The Tagger (Component A) still tags each request in isolation; this
module remembers things *across* requests within the same run_id. C1-C4 read
from it; decision.py writes to it once per request.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from app.tagger import TaggedRequest

UNTRUSTED_TRUST_LEVELS = {"untrusted_internal", "untrusted_external", "adversary_controlled"}

# Tuning knobs. These are calibration choices, not derived constants — call
# them out as such in the technical report's ablation section.
CUMULATIVE_DECAY = 0.85  # running score is multiplied by this before adding each new action's score
CUMULATIVE_ALERT_THRESHOLD = 150.0  # on the same 0-100 scale as ActionIdentity.risk_score
FRAGMENT_BUFFER_SIZE = 12  # how many recent untrusted observations to retain per run
SESSION_TTL_SECONDS = 3600  # evict a run's state if untouched this long (avoids unbounded memory growth)


@dataclass
class DecisionRecord:
    """One entry in a run's decision history, kept for the cumulative score and for
    the observability trace (component E) to explain *why* the cumulative score is
    what it is at any point in the run."""

    step_id: int
    tool: str | None
    decision: str
    action_risk_score: float  # the 0-100 score from ActionIdentity for this one action
    reason_codes: list[str] = field(default_factory=list)


@dataclass
class SessionState:
    """Everything the defense remembers about one run (one ``run_id``), across all
    of that run's steps."""

    run_id: str
    cumulative_risk: float = 0.0
    decisions: list[DecisionRecord] = field(default_factory=list)
    untrusted_fragments: list[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    # How many items of request.conversation have already been folded into
    # untrusted_fragments for this run. The tagger re-tags the FULL cumulative
    # conversation on every call (it is stateless), so without this counter
    # the same untrusted observation would be re-appended on every later step.
    ingested_observation_count: int = 0

    def record_decision(
        self,
        step_id: int,
        tool: str | None,
        decision: str,
        action_risk_score: float,
        reason_codes: list[str],
    ) -> None:
        """Call once per request, after your decision is finalized."""
        self.decisions.append(
            DecisionRecord(
                step_id=step_id,
                tool=tool,
                decision=decision,
                action_risk_score=action_risk_score,
                reason_codes=list(reason_codes),
            )
        )
        self.cumulative_risk = self.cumulative_risk * CUMULATIVE_DECAY + action_risk_score
        self.last_seen = time.time()

    def remember_untrusted_fragment(self, text: str) -> None:
        if not text:
            return
        self.untrusted_fragments.append(text)
        if len(self.untrusted_fragments) > FRAGMENT_BUFFER_SIZE:
            self.untrusted_fragments.pop(0)
        self.last_seen = time.time()

    @property
    def is_cumulative_risk_high(self) -> bool:
        return self.cumulative_risk >= CUMULATIVE_ALERT_THRESHOLD

    def recent_untrusted_text(self) -> str:
        """Concatenated recent untrusted fragments — search this for an instruction
        an attacker split across several records."""
        return " ".join(self.untrusted_fragments)


class SessionStore:
    """Process-wide, in-memory registry of SessionState, keyed by run_id.

    Thread-safe within a single uvicorn worker process. This is NOT shared across
    multiple worker processes or machines: if you ever run this service with
    ``--workers > 1``, cumulative risk and the fragment buffer will be inconsistent
    between workers, since each has its own SessionStore. For SENTINEL's local
    single-process self-testing (``uvicorn app.main:app --port 8080``) this is not a
    concern. Note it as a known limitation in the responsible-AI statement if you
    ever scale the service up.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()

    def get_or_create(self, run_id: str) -> SessionState:
        with self._lock:
            self._evict_stale()
            if run_id not in self._sessions:
                self._sessions[run_id] = SessionState(run_id=run_id)
            return self._sessions[run_id]

    def _evict_stale(self) -> None:
        now = time.time()
        stale_ids = [rid for rid, s in self._sessions.items() if now - s.last_seen > SESSION_TTL_SECONDS]
        for rid in stale_ids:
            del self._sessions[rid]


# One store per running defense process. decide() is called once per HTTP request
# by the same long-lived uvicorn process, so a module-level singleton is what makes
# state actually persist across the steps of a run.
session_store = SessionStore()


def update_session_with_new_observations(run_id: str, tagged: TaggedRequest) -> SessionState:
    """Feed this step's NEW untrusted observations into the run's fragment buffer.

    Call this once per request, right after ``tagger.tag_request(request)`` and
    before your decision logic runs, so C1-C4 can see fragments from earlier steps
    of the same run too, not just the current one.

    ``tagged.observations`` is rebuilt from the FULL cumulative conversation on
    every call (the Tagger is stateless by design). Only observations at index
    >= ``ingested_observation_count`` are new since the last call; re-processing
    earlier ones would duplicate them in the fragment buffer.
    """
    session = session_store.get_or_create(run_id)
    new_observations = tagged.observations[session.ingested_observation_count :]
    for obs in new_observations:
        if obs.trust_level in UNTRUSTED_TRUST_LEVELS:
            session.remember_untrusted_fragment(obs.content)
    session.ingested_observation_count = len(tagged.observations)
    return session