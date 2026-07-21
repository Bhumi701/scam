import uuid
import time
import logging
from typing import Dict, Any, Optional
from threading import Lock

# Configure logger
logger = logging.getLogger("scam_detector.session_manager")
logging.basicConfig(level=logging.INFO)


class Session:
    """
    Represents an active real-time call tracking session.
    """
    def __init__(self, session_id: str):
        self.session_id: str = session_id
        self.transcript: str = ""
        self.running_score: float = 0.0
        self.last_active: float = time.time()
        self.signals: Dict[str, Any] = {}
        # Thread lock for safety during concurrent chunk processing on the same session
        self.lock: Lock = Lock()

    def update_activity(self):
        self.last_active = time.time()


class SessionManager:
    """
    In-memory thread-safe store managing real-time detection sessions.
    No database requirements. Holds state in a local dictionary.
    """
    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._lock: Lock = Lock()

    def create_session(self) -> str:
        """
        Creates a new session and returns its unique session ID.
        """
        session_id = str(uuid.uuid4())
        session = Session(session_id)
        
        with self._lock:
            self._sessions[session_id] = session
            
        logger.info(f"Created real-time session: {session_id}")
        return session_id

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieves a session by ID. Returns None if it does not exist.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.update_activity()
            return session

    def delete_session(self, session_id: str) -> bool:
        """
        Deletes a session from memory. Returns True if deleted, False if not found.
        """
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.info(f"Cleaned up and deleted session: {session_id}")
                return True
            return False

    def cleanup_inactive_sessions(self, max_idle_seconds: int = 1800):
        """
        Periodically purges sessions that have exceeded the idle threshold.
        Default idle threshold is set to 30 minutes.
        """
        now = time.time()
        to_delete = []
        
        with self._lock:
            for sid, sess in self._sessions.items():
                if now - sess.last_active > max_idle_seconds:
                    to_delete.append(sid)
            
            for sid in to_delete:
                del self._sessions[sid]
                
        if to_delete:
            logger.info(f"Automatically purged {len(to_delete)} inactive real-time sessions.")

    def process_accumulated_score(self, session_id: str, current_chunk_score: float) -> float:
        """
        Calculates and updates running session score based on the leaky integrator formula:
        new_score = (previous_score * 0.7) + (current_chunk_score * 0.3)
        Scores decay slowly, remaining elevated even if a clean chunk arrives.
        """
        session = self.get_session(session_id)
        if not session:
            raise KeyError(f"Session with ID {session_id} does not exist.")

        with session.lock:
            previous_score = session.running_score
            new_score = (previous_score * 0.7) + (current_chunk_score * 0.3)
            
            # Enforce clean bounds safety [0.0, 1.0]
            new_score = max(0.0, min(1.0, new_score))
            session.running_score = new_score
            session.update_activity()
            
            logger.info(
                f"Session {session_id} score update: Prev={previous_score:.4f}, "
                f"Chunk={current_chunk_score:.4f}, New={new_score:.4f}"
            )
            return new_score


# Global Singleton Session Manager Instance
session_manager = SessionManager()