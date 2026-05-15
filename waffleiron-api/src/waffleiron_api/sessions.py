"""In-memory session store with TTL-based expiry."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from waffleiron.analysis import AnalysisResult
from waffleiron.decisions import DecisionSet
from waffleiron.model import AsmPolicy
from waffleiron.translators import TranslationResult


@dataclass
class Session:
    """Mutable conversion session holding all state for one policy conversion."""

    id: str
    created_at: float
    status: str = "created"
    policy_name: str | None = None
    policy_file_content: str | None = None
    asm_policy: AsmPolicy | None = None
    analysis: AnalysisResult | None = None
    decisions: DecisionSet = field(default_factory=DecisionSet)
    translation: TranslationResult | None = None
    push_results: dict = field(default_factory=dict)


class SessionStore:
    """Dict-backed session store with automatic TTL expiry."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._sessions: dict[str, Session] = {}
        self._ttl_seconds = ttl_seconds

    def create(self) -> str:
        """Create a new session and return its ID."""
        session_id = uuid.uuid4().hex
        self._sessions[session_id] = Session(
            id=session_id,
            created_at=time.monotonic(),
        )
        return session_id

    def get(self, session_id: str) -> Session | None:
        """Return the session if it exists, otherwise None."""
        return self._sessions.get(session_id)

    def delete(self, session_id: str) -> None:
        """Remove a session by ID (no-op if missing)."""
        self._sessions.pop(session_id, None)

    def cleanup_expired(self) -> None:
        """Remove all sessions whose TTL has elapsed."""
        now = time.monotonic()
        expired = [
            sid
            for sid, session in self._sessions.items()
            if (now - session.created_at) >= self._ttl_seconds
        ]
        for sid in expired:
            del self._sessions[sid]
