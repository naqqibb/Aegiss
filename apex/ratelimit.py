"""A monotonic token-bucket rate limiter.

Used to keep APEX inside each provider's request quota. It refills continuously
at ``rate`` tokens/second up to ``capacity`` and blocks (via an injected sleep)
until a token is available, so bursts are smoothed rather than rejected.
"""

from __future__ import annotations

import time
from typing import Callable


class TokenBucket:
    def __init__(
        self,
        rate: float,
        capacity: float | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(1.0, rate)
        self._tokens = self.capacity
        self._last = clock()
        self._clock = clock
        self._sleep = sleep

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last = now

    def acquire(self, tokens: float = 1.0) -> float:
        """Acquire ``tokens``, sleeping if necessary. Returns time waited."""
        if tokens > self.capacity:
            raise ValueError("requested tokens exceed bucket capacity")
        waited = 0.0
        self._refill()
        while self._tokens < tokens:
            deficit = tokens - self._tokens
            delay = deficit / self.rate
            self._sleep(delay)
            waited += delay
            self._refill()
        self._tokens -= tokens
        return waited
