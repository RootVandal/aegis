from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.routes.alerts import alert_summary
from app.db.session import get_db
from app.detection.registry import RULES_BY_ID
from app.schemas.detection import AlertSummary, DetectionRunOut
from app.schemas.events import IngestionBatchOut
from app.schemas.investigation import IncidentSummary
from app.services.dashboard import Range, build_dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class DataSummaryOut(BaseModel):
    events_total: int
    synthetic_events: int
    imported_events: int
    earliest_event_at: datetime | None
    latest_event_at: datetime | None


class CurrentStateOut(BaseModel):
    alerts_new: int
    alerts_open: int = Field(description="new + acknowledged + investigating")
    incidents_open: int = Field(description="every status except resolved")


class TimePoint(BaseModel):
    start: datetime
    synthetic: int
    imported: int


class EventsOverTime(BaseModel):
    bucket: Literal["hour", "day", "month"]
    points: list[TimePoint]


class RuleCount(BaseModel):
    rule_id: str
    name: str
    count: int


class InRangeOut(BaseModel):
    events: int
    alerts: int = Field(description="Alerts whose evidence ends inside the range.")
    alert_severity: dict[str, int]
    top_rules: list[RuleCount]
    events_over_time: EventsOverTime


class DashboardOut(BaseModel):
    range: Range
    start: datetime | None
    end: datetime
    generated_at: datetime
    data: DataSummaryOut
    current: CurrentStateOut
    in_range: InRangeOut
    recent_alerts: list[AlertSummary]
    recent_incidents: list[IncidentSummary]
    recent_batches: list[IngestionBatchOut]
    last_detection_run: DetectionRunOut | None


@router.get("", response_model=DashboardOut, summary="Overview dashboard")
def dashboard(
    db: Annotated[Session, Depends(get_db)],
    range: Annotated[Range, Query(description="Window ending now.")] = "all",  # noqa: A002
) -> DashboardOut:
    """All figures are computed from stored data at request time. The range is
    anchored to the current time; ``data.latest_event_at`` shows how fresh the
    stored data is."""
    raw = build_dashboard(db, range)
    in_range = raw["in_range"]
    return DashboardOut(
        range=raw["range"],
        start=raw["start"],
        end=raw["end"],
        generated_at=raw["generated_at"],
        data=DataSummaryOut(**raw["data"]),
        current=CurrentStateOut(**raw["current"]),
        in_range=InRangeOut(
            events=in_range["events"],
            alerts=in_range["alerts"],
            alert_severity=in_range["alert_severity"],
            top_rules=[
                RuleCount(
                    rule_id=item["rule_id"],
                    name=RULES_BY_ID[item["rule_id"]].name
                    if item["rule_id"] in RULES_BY_ID
                    else item["rule_id"],
                    count=item["count"],
                )
                for item in in_range["top_rules"]
            ],
            events_over_time=EventsOverTime(**in_range["events_over_time"]),
        ),
        recent_alerts=[alert_summary(a) for a in raw["recent_alerts"]],
        recent_incidents=[
            IncidentSummary(
                id=i.id,
                title=i.title,
                severity=i.severity,
                status=i.status,
                verdict=i.verdict,
                created_at=i.created_at,
                updated_at=i.updated_at,
                alert_count=len(i.alerts),
            )
            for i in raw["recent_incidents"]
        ],
        recent_batches=[IngestionBatchOut.model_validate(b) for b in raw["recent_batches"]],
        last_detection_run=DetectionRunOut.model_validate(raw["last_detection_run"])
        if raw["last_detection_run"]
        else None,
    )
