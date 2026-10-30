"""Enumerations shared by models, schemas and (later) the detection engine."""

from enum import StrEnum


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataOrigin(StrEnum):
    """Where a piece of data came from. Shown in the UI on every dataset."""

    SYNTHETIC = "synthetic"  # generated or bundled training/sample data
    IMPORTED = "imported"  # supplied by the user through the import API


class IngestionStatus(StrEnum):
    COMPLETED = "completed"  # every record accepted or skipped as duplicate
    PARTIAL = "partial"  # some records rejected as invalid
    FAILED = "failed"  # nothing could be stored


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class DetectionTrigger(StrEnum):
    MANUAL = "manual"  # started by a user from the UI or API
    INGESTION = "ingestion"  # started automatically after new events were stored
