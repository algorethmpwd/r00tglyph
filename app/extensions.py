from flask_sqlalchemy import SQLAlchemy
import time
from collections import defaultdict

db = SQLAlchemy()

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self._redis = None
        self._check_redis()

    def _check_redis(self):
        import os
        redis_url = os.environ.get("REDIS_URL")
        if redis_url:
            try:
                import redis
                self._redis = redis.from_url(redis_url)
                self._redis.ping()
            except Exception:
                self._redis = None

    def is_allowed(self, key, max_requests, window_seconds):
        if self._redis:
            try:
                r_key = f"rl:{key}"
                current = self._redis.incr(r_key)
                if current == 1:
                    self._redis.expire(r_key, window_seconds)
                return current <= max_requests
            except Exception:
                self._redis = None

        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
        if len(self.requests[key]) >= max_requests:
            return False
        self.requests[key].append(now)
        return True

    def get_remaining(self, key, max_requests, window_seconds):
        if self._redis:
            try:
                r_key = f"rl:{key}"
                val = self._redis.get(r_key)
                current = int(val) if val else 0
                return max(0, max_requests - current)
            except Exception:
                self._redis = None

        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
        return max(0, max_requests - len(self.requests[key]))

rate_limiter = RateLimiter()
