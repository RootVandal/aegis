"""Detection rules and detection runs."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.base import utc_now
from app.db.session import get_db
from app.detection.mitre import ATTACK_VERSION
from app.detection.registry import RULES
from app.detection.rule import Rule
from app.models import Alert, DetectionRun, RuleSetting
from app.models.enums import DetectionTrigger
from app.schemas.detection import (
    DetectionRunOut,
    MitreDetail,
    MitreSummary,
    RuleChangeOut,
    RuleDetail,
    RuleSummary,
    RuleUpdate,
)
from app.services.detection import get_rule, rule_settings, run_detection

router = APIRouter()


def _alert_counts(db: Session) -> dict[str, int]:
    rows = db.execute(select(Alert.rule_id, func.count()).group_by(Alert.rule_id))
    return {rule_id: count for rule_id, count in rows}


def _summary(rule: Rule[Any], setting: RuleSetting | None, alert_count: int) -> RuleSummary:
    return RuleSummary(
        id=rule.id,
        name=rule.name,
        version=rule.version,
        description=rule.description,
        severity=rule.severity,
        enabled=setting.enabled if setting else True,
        customized=bool(setting and setting.params),
        event_types=list(rule.event_types),
        mitre=[
            MitreSummary(
                id=m.technique.id,
                name=m.technique.name,
                tactics=list(m.technique.tactics),
                url=m.technique.url,
            )
            for m in rule.mitre
        ],
        alert_count=alert_count,
    )


def _detail(rule: Rule[Any], setting: RuleSetting | None, alert_count: int) -> RuleDetail:
    overrides = setting.params if setting else {}
    return RuleDetail(
        **_summary(rule, setting, alert_count).model_dump(),
        logic=list(rule.logic),
        required_fields=list(rule.required_fields),
        mitre_details=[
            MitreDetail(
                id=m.technique.id,
                name=m.technique.name,
                tactics=list(m.technique.tactics),
                url=m.technique.url,
                relationship=m.relationship,
                telemetry=m.telemetry,
                limitations=m.limitations,
            )
            for m in rule.mitre
        ],
        investigation_steps=list(rule.investigation_steps),
        false_positives=list(rule.false_positives),
        limitations=list(rule.limitations),
        unknowns=list(rule.unknowns),
        changelog=[
            RuleChangeOut(version=c.version, date=c.date, description=c.description)
            for c in rule.changelog
        ],
        params=rule.parse_params(overrides).model_dump(mode="json"),
        default_params=rule.parse_params({}).model_dump(mode="json"),
        overrides=overrides,
        params_schema=rule.params_model.model_json_schema(),
        attack_version=ATTACK_VERSION,
    )


@router.get("/rules", response_model=list[RuleSummary], tags=["rules"], summary="Detection rules")
def list_rules(db: Annotated[Session, Depends(get_db)]) -> list[RuleSummary]:
    settings, counts = rule_settings(db), _alert_counts(db)
    return [_summary(rule, settings.get(rule.id), counts.get(rule.id, 0)) for rule in RULES]


@router.get("/rules/{rule_id}", response_model=RuleDetail, tags=["rules"], summary="Rule details")
def rule_detail(rule_id: str, db: Annotated[Session, Depends(get_db)]) -> RuleDetail:
    rule = get_rule(rule_id)
    return _detail(rule, db.get(RuleSetting, rule_id), _alert_counts(db).get(rule_id, 0))


@router.patch(
    "/rules/{rule_id}", response_model=RuleDetail, tags=["rules"], summary="Configure a rule"
)
def update_rule(
    rule_id: str, update: RuleUpdate, db: Annotated[Session, Depends(get_db)]
) -> RuleDetail:
    """Enable/disable a rule or replace its parameter overrides.

    Changes apply to the next detection run. Existing alerts keep the
    parameters they were created with.
    """
    rule = get_rule(rule_id)
    setting = db.get(RuleSetting, rule_id) or RuleSetting(rule_id=rule_id, enabled=True, params={})
    if update.params is not None:
        try:
            rule.parse_params(update.params)
        except ValidationError as exc:
            details = [
                {"loc": ["body", "params", *map(str, e["loc"])], "msg": e["msg"], "type": e["type"]}
                for e in exc.errors()
            ]
            raise AppError(
                422, "invalid_rule_params", "Invalid rule parameters.", details
            ) from None
        setting.params = update.params
    if update.enabled is not None:
        setting.enabled = update.enabled
    setting.updated_at = utc_now()
    db.add(setting)
    db.commit()
    return _detail(rule, setting, _alert_counts(db).get(rule_id, 0))


@router.post(
    "/detections/runs",
    response_model=DetectionRunOut,
    status_code=201,
    tags=["detections"],
    summary="Run all enabled rules now",
)
def start_run(db: Annotated[Session, Depends(get_db)]) -> DetectionRunOut:
    """Evaluates every enabled rule over all stored events. Safe to repeat:
    findings that already have an alert are counted, not duplicated."""
    return DetectionRunOut.model_validate(run_detection(db, DetectionTrigger.MANUAL))


@router.get(
    "/detections/runs",
    response_model=list[DetectionRunOut],
    tags=["detections"],
    summary="Recent detection runs",
)
def list_runs(
    db: Annotated[Session, Depends(get_db)], limit: Annotated[int, Query(ge=1, le=100)] = 20
) -> list[DetectionRunOut]:
    runs = db.scalars(select(DetectionRun).order_by(DetectionRun.id.desc()).limit(limit))
    return [DetectionRunOut.model_validate(run) for run in runs]
