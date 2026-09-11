"""Alert transport: a small pub/sub bus with pluggable sinks."""

from __future__ import annotations

import sys
from typing import Callable, List

from .models import Alert, Severity

Sink = Callable[[Alert], None]


class AlertBus:
    """Fan out alerts to any number of sinks, above a minimum severity."""

    def __init__(self, min_severity: Severity = Severity.INFO) -> None:
        self.min_severity = min_severity
        self._sinks: List[Sink] = []

    def subscribe(self, sink: Sink) -> Sink:
        self._sinks.append(sink)
        return sink

    def publish(self, alert: Alert) -> bool:
        """Dispatch ``alert`` to all sinks. Returns True if it was emitted."""

        if alert.severity < self.min_severity:
            return False
        for sink in self._sinks:
            sink(alert)
        return True


class MemorySink:
    """Collect alerts in memory; handy for tests and dashboards."""

    def __init__(self) -> None:
        self.alerts: List[Alert] = []

    def __call__(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def clear(self) -> None:
        self.alerts.clear()


class ConsoleSink:
    """Write alerts to a stream (stderr by default)."""

    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stderr

    def __call__(self, alert: Alert) -> None:
        print(alert.as_line(), file=self.stream)
