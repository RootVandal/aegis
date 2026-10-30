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


class IncidentStatus(StrEnum):
    """Basic lifecycle: new -> investigating -> contained -> resolved."""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class NoteKind(StrEnum):
    NOTE = "note"  # an observation or action taken
    HYPOTHESIS = "hypothesis"  # an unverified explanation; always labeled as such


class AssessmentVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"  # malicious or unauthorized activity confirmed
    BENIGN_ACTIVITY = "benign_activity"  # the activity happened but was authorized/expected
    FALSE_POSITIVE = "false_positive"  # the detection was wrong about what happened
    INCONCLUSIVE = "inconclusive"  # the evidence does not support a conclusion


class AttemptStatus(StrEnum):
    IN_PROGRESS = "in_progress"
    SUBMITTED = "submitted"  # graded; explanation unlocked
    REVEALED = "revealed"  # analyst asked for the explanation without submitting
