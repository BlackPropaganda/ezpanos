from dataclasses import dataclass, asdict

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Interface:
    name: str
    ip: Optional[str] = None
    zone: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Network:
    interfaces: List[Interface] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Device:
    hostname: Optional[str]
    network: Network
    username: str | None
    password: str | None
    api_key: str | None
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PanosConfig:
    devices: List[Device]
    raw: Dict[str, Any] = field(default_factory=dict)

