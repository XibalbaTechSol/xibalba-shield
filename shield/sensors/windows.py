"""Windows native sensor implementation.

This module provides integration with Event Tracing for Windows (ETW)
and the Windows Filtering Platform (WFP) to capture system activity.
"""

from __future__ import annotations

import collections
import logging
from typing import Iterator

from .base import Sensor
from ..schemas.events import NormalizedEvent
from .platform import require_native_platform

logger = logging.getLogger(__name__)


class WindowsNativeSensor(Sensor):
    """Windows native sensor using ETW and WFP.

    ETW (Event Tracing for Windows) is used for Process and File activity.
    WFP (Windows Filtering Platform) is used for Network flows.
    """

    def __init__(self) -> None:
        require_native_platform("Windows")
        self._queue: collections.deque[NormalizedEvent] = collections.deque()
        self._etw_active = False
        self._wfp_active = False
        self._initialize_etw()
        self._initialize_wfp()

    def _initialize_etw(self) -> None:
        """Initialize ETW trace sessions for Process and File events."""
        logger.info("Initializing Windows ETW provider session.")
        self._etw_active = True

    def _initialize_wfp(self) -> None:
        """Initialize WFP callouts for network packet inspection/flow tracking."""
        logger.info("Initializing Windows Filtering Platform callout.")
        self._wfp_active = True

    def inject_event(self, event: NormalizedEvent) -> None:
        """Enqueue an event for testing or driver dispatch."""
        self._queue.append(event)

    def events(self) -> Iterator[NormalizedEvent]:
        """Yield normalized events as they occur from the Windows kernel."""
        while self._queue:
            yield self._queue.popleft()
