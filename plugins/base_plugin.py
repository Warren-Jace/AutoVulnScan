from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """
    A simple data class to represent a found vulnerability.
    """
    injection_url: str
    trigger_url: Optional[str] # URL where the vulnerability was triggered
    plugin_name: str
    description: str
    confidence: str
    severity: str
    payload: str
    param: Dict[str, Any]


class BasePlugin(ABC):
    """
    Abstract base class for all scanner plugins.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Returns the name of the plugin.
        """
        raise NotImplementedError
