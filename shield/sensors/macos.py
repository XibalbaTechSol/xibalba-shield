"""macOS native sensor implementation outline.

This module outlines the integration with the macOS EndpointSecurity framework
and NetworkExtension for system telemetry.
"""

from __future__ import annotations

from typing import Iterator

from .base import Sensor
from ..schemas.events import NormalizedEvent
from .platform import require_native_platform

class MacOSNativeSensor(Sensor):
    """
    macOS native sensor using EndpointSecurity (ES) and NetworkExtension (NE).
    
    ES provides callbacks for Process Exec and File modifications.
    NE provides network flow data (or alternatively using BPF/libpcap).
    """
    
    def __init__(self) -> None:
        require_native_platform("Darwin")
        self._initialize_endpoint_security()
        self._initialize_network_extension()
        
    def _initialize_endpoint_security(self) -> None:
        """Initialize EndpointSecurity clients and subscribe to AUTH/NOTIFY events."""
        # TODO: Implement via ctypes/cffi calling into libEndpointSecurity.dylib (es_new_client, es_subscribe)
        # Note: Requires specific entitlements (com.apple.developer.endpoint-security.client) and root privileges.
        pass
        
    def _initialize_network_extension(self) -> None:
        """Initialize NetworkExtension or packet filter for network flows."""
        # TODO: Implement network monitoring.
        pass

    def events(self) -> Iterator[NormalizedEvent]:
        """Yield normalized events as they occur from the macOS kernel."""
        # Conceptual loop:
        # while True:
        #     raw_event = self._es_queue_get()
        #     yield self._normalize(raw_event)
        
        # Placeholder yielding nothing for now
        yield from []
