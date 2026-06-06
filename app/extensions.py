from flask_sqlalchemy import SQLAlchemy
import time
from collections import defaultdict

db = SQLAlchemy()

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)

    def is_allowed(self, key, max_requests, window_seconds):
        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
        if len(self.requests[key]) >= max_requests:
            return False
        self.requests[key].append(now)
        return True

    def get_remaining(self, key, max_requests, window_seconds):
        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
        return max(0, max_requests - len(self.requests[key]))

rate_limiter = RateLimiter()
