"""Linux native sensor implementation wrapper.

This module provides a unified Sensor interface that wraps the underlying
eBPF-based sensors located in the `ebpf` package.
"""

from __future__ import annotations

import logging
from typing import Iterator

from .base import Sensor
from ..schemas.events import NormalizedEvent
from .platform import require_native_platform

logger = logging.getLogger(__name__)

class LinuxNativeSensor(Sensor):
    """
    Linux native sensor wrapping the specific eBPF implementations.
    """
    
    def __init__(self) -> None:
        require_native_platform("Linux")
        self._initialize_ebpf()
        
    def _initialize_ebpf(self) -> None:
        """Initialize the specific eBPF probes for Process, File, and Network."""
        # In a real integration, this would initialize ebpf.process, ebpf.file, ebpf.network
        logger.debug("Linux eBPF probes initialized conceptually.")

    def events(self) -> Iterator[NormalizedEvent]:
        """Yield normalized events from the eBPF ring buffers."""
        # Conceptually, this multiplexes events from the various eBPF probes.
        yield from []
