"""
Incident storage repository.

Local development uses an in-memory store. AWS deployments can set
AIDOCTOR_DYNAMODB_TABLE to persist incidents in DynamoDB. The same repository
interface is kept so the rest of the backend does not care which store is used.
"""

import os
from decimal import Decimal
from threading import Lock
from typing import Dict, List, Optional, Any

from .models import Incident
from runner.redaction import sanitize_deep


def _to_dynamo(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_dynamo(v) for v in value]
    return value


def _from_dynamo(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value) if value % 1 else int(value)
    if isinstance(value, dict):
        return {k: _from_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_dynamo(v) for v in value]
    return value


class IncidentRepository:
    """Incident repository with an optional DynamoDB persistence layer."""

    def __init__(self):
        self._items: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._table_name = os.environ.get("AIDOCTOR_DYNAMODB_TABLE", "").strip()
        self._table = None
        self._dynamo_error: Optional[str] = None

        if self._table_name:
            try:
                import boto3
                self._table = boto3.resource("dynamodb").Table(self._table_name)
            except Exception as exc:
                # Do not prevent local/test imports when the optional AWS SDK
                # or credentials are unavailable. The status is exposed through
                # the repository property for diagnostics.
                self._dynamo_error = f"{type(exc).__name__}: {exc}"

    @property
    def persistent(self) -> bool:
        return self._table is not None

    @property
    def persistence_error(self) -> Optional[str]:
        return self._dynamo_error

    def save(self, incident: Incident) -> Incident:
        data = sanitize_deep(incident.to_dynamodb_item())

        if self._table is not None:
            self._table.put_item(Item=_to_dynamo(data))
            return incident

        with self._lock:
            self._items[incident.incident_id] = data
        return incident

    def get(self, incident_id: str) -> Optional[Incident]:
        if self._table is not None:
            response = self._table.get_item(Key={"incident_id": incident_id})
            data = response.get("Item")
            return Incident(**_from_dynamo(data)) if data else None

        with self._lock:
            data = self._items.get(incident_id)
            return Incident(**data) if data else None

    def list_all(self, limit: int = 50, status: Optional[str] = None) -> List[Incident]:
        if self._table is not None:
            response = self._table.scan(Limit=max(1, min(limit, 100)))
            items = [_from_dynamo(item) for item in response.get("Items", [])]
        else:
            with self._lock:
                items = list(self._items.values())

        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        if status:
            items = [i for i in items if i.get("status") == status]
        return [Incident(**i) for i in items[:limit]]

    def update(self, incident_id: str, updates: Dict[str, Any]) -> Optional[Incident]:
        current = self.get(incident_id)
        if current is None:
            return None

        merged = current.model_dump()
        merged.update(updates)
        updated = Incident(**sanitize_deep(merged))
        self.save(updated)
        return updated

    def get_latest(self) -> Optional[Incident]:
        items = self.list_all(limit=1)
        return items[0] if items else None

    def clear(self):
        if self._table is not None:
            # Clear is intentionally unsupported for production tables.
            return
        with self._lock:
            self._items.clear()


incident_repo = IncidentRepository()
