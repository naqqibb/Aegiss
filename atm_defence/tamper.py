"""Physical tamper / skimmer signal monitoring.

ATMs expose sensors on the card reader, chassis, PIN pad and camera. This
monitor tracks a short rolling baseline per (atm, sensor) and raises an alert
when a reading deviates sharply from that baseline, which is characteristic of
a skimmer overlay, a jackpotting attack, or a blocked surveillance camera.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from .models import Alert, Severity, TamperEvent

# Severity assigned to a confirmed tamper, keyed by sensor kind.
_KIND_SEVERITY: Dict[str, Severity] = {
    "card_reader": Severity.CRITICAL,  # skimmer overlay
    "chassis": Severity.CRITICAL,      # jackpotting / physical breach
    "camera_block": Severity.HIGH,
    "vibration": Severity.MEDIUM,
    "pin_pad": Severity.HIGH,
}


class TamperMonitor:
    """Rolling-baseline anomaly detector for physical sensor readings."""

    def __init__(self, baseline: int = 20, sensitivity: float = 0.35,
                 absolute_trip: float = 0.9) -> None:
        """
        :param baseline: number of recent samples used for the baseline mean.
        :param sensitivity: minimum jump above the baseline mean to alert.
        :param absolute_trip: reading at/above which we always alert,
            regardless of baseline (a hard safety trip).
        """
        if not 0 < sensitivity <= 1:
            raise ValueError("sensitivity must be in (0, 1]")
        self.baseline = baseline
        self.sensitivity = sensitivity
        self.absolute_trip = absolute_trip
        self._history: Dict[Tuple[str, str], Deque[float]] = defaultdict(
            lambda: deque(maxlen=self.baseline)
        )

    def observe(self, event: TamperEvent) -> Optional[Alert]:
        """Feed one sensor reading; return an Alert if it looks like tampering."""

        key = (event.atm_id, event.kind)
        hist = self._history[key]
        mean = sum(hist) / len(hist) if hist else 0.0
        # Record the sample for future baselines before deciding.
        hist.append(event.value)

        tripped = event.value >= self.absolute_trip
        deviated = bool(hist) and (event.value - mean) >= self.sensitivity

        if tripped or (deviated and len(hist) > 1):
            sev = _KIND_SEVERITY.get(event.kind, Severity.MEDIUM)
            reason = "hard trip" if tripped else f"deviation +{event.value - mean:.2f} vs baseline {mean:.2f}"
            return Alert(
                rule="tamper",
                severity=sev,
                message=f"{event.kind} sensor {event.value:.2f} ({reason})",
                atm_id=event.atm_id,
                ts=event.ts,
            )
        return None
