"""Request and response models for rules, detection runs and alerts."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AlertStatus, DetectionTrigger, Severity
from app.schemas.events import EventSummary, IngestionResponse


class MitreSummary(BaseModel):
    id: str
    name: str
    tactics: list[str]
    url: str


class MitreDetail(MitreSummary):
    relationship: str
    telemetry: str
    limitations: str


class RuleChangeOut(BaseModel):
    version: int
    date: str
    description: str


class RuleSummary(BaseModel):
    id: str
    name: str
    version: int
    description: str
    severity: Severity
    enabled: bool
    customized: bool = Field(description="True when parameters differ from the rule defaults.")
    event_types: list[str]
    mitre: list[MitreSummary]
    alert_count: int


class RuleDetail(RuleSummary):
    logic: list[str]
    required_fields: list[str]
    mitre_details: list[MitreDetail]
    investigation_steps: list[str]
    false_positives: list[str]
    limitations: list[str]
    unknowns: list[str]
    changelog: list[RuleChangeOut]
    params: dict[str, Any] = Field(description="Effective parameters (defaults + overrides).")
    default_params: dict[str, Any]
    overrides: dict[str, Any]
    params_schema: dict[str, Any] = Field(description="JSON Schema of the parameters.")
    attack_version: str


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    params: dict[str, Any] | None = Field(
        default=None,
        description="Replaces all overrides. Send {} to return to the defaults.",
    )


class DetectionRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    trigger: DetectionTrigger
    started_at: datetime
    completed_at: datetime | None
    events_evaluated: int
    findings_count: int
    alerts_created: int
    alerts_existing: int
    rules: list[dict[str, Any]]


class AlertFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: list[AlertStatus] = Field(default_factory=list)
    severity: list[Severity] = Field(default_factory=list)
    rule_id: str | None = Field(default=None, max_length=64)
    q: str | None = Field(default=None, max_length=200, description="Search in alert titles.")
    sort: Literal["last_seen_desc", "created_desc", "severity_desc"] = "last_seen_desc"
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class AlertSummary(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    rule_version: int
    title: str
    severity: Severity
    status: AlertStatus
    created_at: datetime
    first_seen: datetime
    last_seen: datetime
    event_count: int
    hosts: list[str]
    users: list[str]
    ips: list[str]
    incident_id: int | None


class AlertDetail(AlertSummary):
    explanation: dict[str, Any]
    rule_params: dict[str, Any]
    detection_run_id: int | None
    events: list[EventSummary]


class AlertPage(BaseModel):
    items: list[AlertSummary]
    total: int
    page: int
    page_size: int


class IngestionWithDetection(IngestionResponse):
    detection: DetectionRunOut | None = Field(
        default=None,
        description="The detection run started automatically after storing new events "
        "(null when nothing new was stored or auto-detection is off).",
    )
