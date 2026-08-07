"""Cross-platform sensor factory.

Dynamically selects and instantiates the correct OS-native sensor based on the current platform,
providing a unified interface for the rest of the application.
"""

from __future__ import annotations

import logging
import platform

from .base import Sensor
from .platform import PlatformNotSupported

logger = logging.getLogger(__name__)

def get_native_sensor() -> Sensor:
    """
    Factory function to return the correct native sensor for the current platform.
    
    This function bridges the conceptual gap between the abstract Sensor interface
    and the OS-specific implementations (eBPF on Linux, ETW/WFP on Windows, 
    EndpointSecurity on macOS).
    """
    sys_platform = platform.system()
    
    if sys_platform == "Linux":
        # In a fully integrated state, this would initialize the eBPF sensors.
        from .linux_sensor import LinuxNativeSensor
        logger.info("Initializing Linux eBPF native sensor.")
        return LinuxNativeSensor()
        
    elif sys_platform == "Windows":
        from .windows import WindowsNativeSensor
        logger.info("Initializing Windows ETW/WFP native sensor.")
        return WindowsNativeSensor()
        
    elif sys_platform == "Darwin":
        from .macos import MacOSNativeSensor
        logger.info("Initializing macOS EndpointSecurity native sensor.")
        return MacOSNativeSensor()
        
    else:
        raise PlatformNotSupported(f"No native sensor implementation for platform: {sys_platform}")
