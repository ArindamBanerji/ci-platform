from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List

class SourceConnectorProtocol(ABC):
    @abstractmethod
    async def fetch_alerts(self, since: datetime, limit: int = 500) -> List[Dict]: ...
    @abstractmethod
    async def write_disposition(self, alert_id: str, disposition: Dict) -> bool: ...
    @abstractmethod
    async def health_check(self) -> Dict: ...
