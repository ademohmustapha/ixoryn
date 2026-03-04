"""
Ixoryn Global Rate Limiter
===========================
Coordinates API call rates across ALL modules to prevent accidental
Terms-of-Service violations when multiple modules run simultaneously.

Without this, running breach_intel + url_audit + cve_lookup concurrently
would fire requests at HIBP, VirusTotal, Shodan, and AbuseIPDB at the
same time with no coordination — each module only knew about its own rate.

Design:
  - Per-API token bucket (sliding window, thread-safe)
  - Default limits are conservative (below official ToS limits)
  - Callers block until a slot is available (no silent dropping)
  - Emergency hard-cap: if a module exceeds burst limit, it backs off

Usage:
    from ixoryn.core.rate_limit import get_limiter

    limiter = get_limiter()
    limiter.acquire("hibp")          # blocks if HIBP rate exceeded
    limiter.acquire("virustotal")
    limiter.acquire("shodan", cost=2) # some endpoints cost more credits
"""
from __future__ import annotations

import threading
import time
from typing import Dict, Optional


# ── Per-API rate limits (requests per second unless noted) ────────────────────
# These are intentionally conservative — well below official ToS limits.
# Adjust via configure() if you have a paid plan with higher allowances.
_DEFAULT_LIMITS: Dict[str, Dict] = {
    "hibp":          {"rps": 0.5,   "burst": 3},   # 1 req / 2s (free tier)
    "virustotal":    {"rps": 0.067, "burst": 2},   # 4 req / min (free tier)
    "shodan":        {"rps": 0.017, "burst": 1},   # 1 req / min (free tier)
    "abuseipdb":     {"rps": 0.2,   "burst": 3},   # 12 req / min (free)
    "nvd":           {"rps": 0.1,   "burst": 5},   # NVD recommends 5/30s
    "cve_circl":     {"rps": 2.0,   "burst": 10},  # circl.lu — lenient
    "generic_web":   {"rps": 5.0,   "burst": 20},  # generic HTTP targets
    "dns":           {"rps": 10.0,  "burst": 50},  # DNS queries
    "default":       {"rps": 1.0,   "burst": 5},   # unknown APIs
}


class _TokenBucket:
    """Thread-safe token bucket with burst support."""

    def __init__(self, rps: float, burst: int) -> None:
        self._rps   = rps
        self._burst = burst
        self._tokens = float(burst)
        self._last  = time.monotonic()
        self._lock  = threading.Lock()

    def acquire(self, cost: float = 1.0, timeout: float = 120.0) -> bool:
        """
        Block until `cost` tokens are available, or *timeout* seconds elapse.

        FIXED: Previously this method looped forever with no timeout or
        cancellation path.  A slow API bucket (e.g. Shodan at 1 req/min)
        would block a UI thread for 60 seconds with no way to interrupt.

        Args:
            cost:    Token cost (default 1.0).
            timeout: Maximum seconds to wait before returning False.
                     Default 120s — generous for slow-rate APIs but not
                     infinite.  Callers should check the return value and
                     surface a warning to the user when False.

        Returns:
            True  — token acquired, caller may proceed.
            False — timeout elapsed; caller should skip or warn.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                if now > deadline:
                    return False
                elapsed = now - self._last
                self._tokens = min(
                    float(self._burst),
                    self._tokens + elapsed * self._rps,
                )
                self._last = now
                if self._tokens >= cost:
                    self._tokens -= cost
                    return True
                wait = (cost - self._tokens) / self._rps
            sleep_for = min(wait, 2.0, max(0.0, deadline - time.monotonic()))
            if sleep_for <= 0:
                return False
            time.sleep(sleep_for)

    def available_tokens(self) -> float:
        with self._lock:
            now = time.monotonic()
            return min(
                float(self._burst),
                self._tokens + (now - self._last) * self._rps,
            )


class GlobalRateLimiter:
    """
    Singleton rate limiter shared across all Ixoryn modules.
    Thread-safe: multiple scanner threads acquire slots from the same buckets.
    """

    def __init__(self) -> None:
        self._buckets: Dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()
        self._call_counts: Dict[str, int] = {}
        for api, limits in _DEFAULT_LIMITS.items():
            self._buckets[api] = _TokenBucket(limits["rps"], limits["burst"])
            self._call_counts[api] = 0

    def acquire(self, api: str, cost: float = 1.0, timeout: float = 120.0) -> bool:
        """
        Block until an API call slot is available, with timeout protection.

        Args:
            api:     API name key (e.g. "hibp", "virustotal", "shodan")
            cost:    Token cost (default 1.0; some endpoints cost more)
            timeout: Maximum seconds to wait (default 120).

        Returns:
            True if token acquired, False if timeout elapsed.
        """
        bucket = self._get_bucket(api)
        acquired = bucket.acquire(cost, timeout=timeout)
        if acquired:
            with self._lock:
                self._call_counts[api] = self._call_counts.get(api, 0) + 1
        return acquired

    def _get_bucket(self, api: str) -> _TokenBucket:
        if api in self._buckets:
            return self._buckets[api]
        # Unknown API — create a bucket from defaults
        with self._lock:
            if api not in self._buckets:
                d = _DEFAULT_LIMITS["default"]
                self._buckets[api] = _TokenBucket(d["rps"], d["burst"])
                self._call_counts[api] = 0
        return self._buckets[api]

    def configure(self, api: str, rps: float, burst: int) -> None:
        """Override rate limits for an API (e.g. when user has a paid plan)."""
        with self._lock:
            self._buckets[api] = _TokenBucket(rps, burst)

    def status(self) -> Dict[str, Dict]:
        """Return current token availability across all APIs."""
        return {
            api: {
                "available_tokens": round(bucket.available_tokens(), 2),
                "calls_made":       self._call_counts.get(api, 0),
            }
            for api, bucket in self._buckets.items()
        }


# ── Module-level singleton ────────────────────────────────────────────────────
_instance: Optional[GlobalRateLimiter] = None
_instance_lock = threading.Lock()


def get_limiter() -> GlobalRateLimiter:
    """Return the process-wide GlobalRateLimiter singleton."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = GlobalRateLimiter()
    return _instance
