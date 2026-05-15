"""Tests for the in-memory session store."""

import time

from waffleiron_api.sessions import Session, SessionStore


class TestSessionStore:
    def test_create_and_get(self):
        store = SessionStore(ttl_seconds=3600)
        session_id = store.create()
        session = store.get(session_id)
        assert session is not None
        assert session.id == session_id

    def test_get_nonexistent(self):
        store = SessionStore(ttl_seconds=3600)
        assert store.get("nonexistent") is None

    def test_delete(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        store.delete(sid)
        assert store.get(sid) is None

    def test_expiry(self):
        store = SessionStore(ttl_seconds=0)  # immediate expiry
        sid = store.create()
        time.sleep(0.1)
        store.cleanup_expired()
        assert store.get(sid) is None

    def test_session_holds_state(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        session = store.get(sid)
        session.policy_name = "test"
        session.status = "analyzed"
        retrieved = store.get(sid)
        assert retrieved.policy_name == "test"
        assert retrieved.status == "analyzed"


class TestSessionDefaults:
    def test_default_status(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        session = store.get(sid)
        assert session.status == "created"

    def test_default_optional_fields_are_none(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        session = store.get(sid)
        assert session.policy_name is None
        assert session.policy_file_content is None
        assert session.asm_policy is None
        assert session.analysis is None
        assert session.translation is None

    def test_default_decisions_is_empty(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        session = store.get(sid)
        # DecisionSet exists and has no decisions
        assert session.decisions is not None
        assert len(session.decisions.signature_decisions) == 0

    def test_default_push_results_is_empty_dict(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        session = store.get(sid)
        assert session.push_results == {}

    def test_multiple_sessions_independent(self):
        store = SessionStore(ttl_seconds=3600)
        sid1 = store.create()
        sid2 = store.create()
        store.get(sid1).policy_name = "policy_a"
        store.get(sid2).policy_name = "policy_b"
        assert store.get(sid1).policy_name == "policy_a"
        assert store.get(sid2).policy_name == "policy_b"

    def test_cleanup_keeps_valid_sessions(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        store.cleanup_expired()
        assert store.get(sid) is not None
