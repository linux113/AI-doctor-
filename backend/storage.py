"""
Incident Storage Repository.
Implements a clean storage interface matching DynamoDB query patterns.
Allows drop-in replacement with boto3 DynamoDB resource in AWS Phase 2.
"""

from typing import Dict, List, Optional, Any
from threading import Lock
from .models import Incident


class IncidentRepository:
    """Document repository for incidents, matching DynamoDB key patterns."""

    def __init__(self):
        self._items: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()

    def save(self, incident: Incident) -> Incident:
        with self._lock:
            data = incident.to_dynamodb_item()
            self._items[incident.incident_id] = data
            return incident

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            data = self._items.get(incident_id)
            if data:
                return Incident(**data)
            return None

    def list_all(self, limit: int = 50, status: Optional[str] = None) -> List[Incident]:
        with self._lock:
            items = list(self._items.values())
            # Sort by created_at descending
            items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            if status:
                items = [i for i in items if i.get("status") == status]
            return [Incident(**i) for i in items[:limit]]

    def update(self, incident_id: str, updates: Dict[str, Any]) -> Optional[Incident]:
        with self._lock:
            if incident_id not in self._items:
                return None
            self._items[incident_id].update(updates)
            return Incident(**self._items[incident_id])

    def get_latest(self) -> Optional[Incident]:
        all_items = self.list_all(limit=1)
        return all_items[0] if all_items else None

    def clear(self):
        with self._lock:
            self._items.clear()


# Global singleton repository
incident_repo = IncidentRepository()
