"""Small in-memory rate limiter (sliding window) with temporary blocks."""
import threading
import time
from collections import deque

_lock = threading.Lock()
_hits: dict[tuple, deque] = {}
_blocked: dict[tuple, float] = {}


def _prune(now: float) -> None:
    for k in [k for k, dq in _hits.items() if not dq or now - dq[-1] > 3600]:
        _hits.pop(k, None)
    for k in [k for k, until in _blocked.items() if until <= now]:
        _blocked.pop(k, None)


def allow(bucket: str, key: str, limit: int, per: float) -> bool:
    """True if this call is within `limit` calls per `per` seconds."""
    now = time.monotonic()
    with _lock:
        dq = _hits.setdefault((bucket, key), deque())
        while dq and now - dq[0] > per:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        if len(_hits) > 5000:
            _prune(now)
        return True


def blocked_for(bucket: str, key: str) -> float:
    """Seconds left on a block, or 0."""
    with _lock:
        until = _blocked.get((bucket, key), 0)
    left = until - time.monotonic()
    return left if left > 0 else 0


def fail(bucket: str, key: str, limit: int, per: float, block_for: float) -> None:
    """Record a failure. After `limit` failures within `per` seconds, block for `block_for` seconds."""
    now = time.monotonic()
    k = (bucket + ":fail", key)
    with _lock:
        dq = _hits.setdefault(k, deque())
        while dq and now - dq[0] > per:
            dq.popleft()
        dq.append(now)
        if len(dq) >= limit:
            _blocked[(bucket, key)] = now + block_for
            dq.clear()
