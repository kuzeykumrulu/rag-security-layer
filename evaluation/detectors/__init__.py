"""Detectors: the measurement half of the system.

Import surface is deliberately small -- callers need a detector for a
category and the verdict type, nothing else.

    from evaluation.detectors import get_detector
    verdict = get_detector(record["category"]).judge(record)

See base.py for why a detector judges raw model output rather than the
filtered answer, and signals.py for why nothing here imports from
detection/.
"""

from .base import Detector, DetectorVerdict
from .categories import DETECTORS, get_detector

__all__ = ["Detector", "DetectorVerdict", "DETECTORS", "get_detector"]
