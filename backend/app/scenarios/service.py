"""Scenario Lab workflow: load data, attempts, hints, grading."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.base import utc_now
from app.ingestion.parser import InputFormat, ParsedRecord
from app.ingestion.service import ingest_records
from app.models import Alert, Event, ScenarioAttempt, alert_events
from app.models.enums import AttemptStatus, DataOrigin, DetectionTrigger
from app.scenarios.catalog import SCENARIOS
from app.scenarios.model import GradeInput, GradingError, Scenario, grade
from app.services.detection import run_detection


def get_scenario(scenario_id: str) -> Scenario:
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise AppError(404, "scenario_not_found", f"No scenario named {scenario_id!r}.")
    return scenario


def loaded_event_ids(session: Session, scenario: Scenario) -> set[str]:
    return set(
        session.scalars(select(Event.event_id).where(Event.scenario_id == scenario.scenario_tag))
    )


def ensure_loaded(session: Session, scenario: Scenario) -> None:
    """Load the scenario's events (idempotent) and run detection if anything was new.

    The data goes through the same normalization, de-duplication and detection
    as any import, so the analyst investigates with the normal tools.
    """
    records = scenario.generate()
    if len(loaded_event_ids(session, scenario)) >= len(records):
        return
    result = ingest_records(
        session,
        [ParsedRecord(i, record=r) for i, r in enumerate(records, start=1)],
        source_name=f"scenario:{scenario.id}",
        input_format=InputFormat.JSON,
        data_origin=DataOrigin.SYNTHETIC,
    )
    if result.batch.accepted_count:
        run_detection(session, DetectionTrigger.INGESTION)


def scenario_alerts(session: Session, scenario: Scenario) -> list[Alert]:
    return list(
        session.scalars(
            select(Alert)
            .where(
                Alert.id.in_(
                    select(alert_events.c.alert_id)
                    .join(Event, Event.id == alert_events.c.event_id)
                    .where(Event.scenario_id == scenario.scenario_tag)
                )
            )
            .order_by(Alert.first_seen, Alert.id)
        )
    )


def attempts_for(session: Session, scenario_id: str) -> list[ScenarioAttempt]:
    return list(
        session.scalars(
            select(ScenarioAttempt)
            .where(ScenarioAttempt.scenario_id == scenario_id)
            .order_by(ScenarioAttempt.id.desc())
        )
    )


def attempt_counts(session: Session) -> dict[str, int]:
    rows = session.execute(
        select(ScenarioAttempt.scenario_id, func.count()).group_by(ScenarioAttempt.scenario_id)
    )
    return {scenario_id: count for scenario_id, count in rows}


def start_attempt(session: Session, scenario: Scenario) -> ScenarioAttempt:
    ensure_loaded(session, scenario)
    attempt = ScenarioAttempt(scenario_id=scenario.id, started_at=utc_now())
    session.add(attempt)
    session.commit()
    return attempt


def get_attempt(session: Session, attempt_id: int) -> ScenarioAttempt:
    attempt = session.get(ScenarioAttempt, attempt_id)
    if attempt is None:
        raise AppError(404, "attempt_not_found", f"No scenario attempt with ID {attempt_id}.")
    return attempt


def _require_open(attempt: ScenarioAttempt) -> None:
    if attempt.status != AttemptStatus.IN_PROGRESS:
        raise AppError(
            409, "attempt_closed", "This attempt is closed. Start a new attempt to try again."
        )


def reveal_hint(session: Session, attempt: ScenarioAttempt) -> ScenarioAttempt:
    _require_open(attempt)
    scenario = get_scenario(attempt.scenario_id)
    if attempt.hints_used >= len(scenario.hints):
        raise AppError(409, "no_more_hints", "All hints for this scenario are already shown.")
    attempt.hints_used += 1
    session.commit()
    return attempt


def submit(session: Session, attempt: ScenarioAttempt, submission: GradeInput) -> ScenarioAttempt:
    _require_open(attempt)
    scenario = get_scenario(attempt.scenario_id)
    try:
        evaluation = grade(scenario, submission, loaded_event_ids(session, scenario))
    except GradingError as exc:
        raise AppError(422, "invalid_submission", str(exc)) from None
    attempt.answers = dict(submission.answers)
    attempt.evidence_event_ids = sorted(set(submission.evidence_event_ids))
    attempt.rationale = submission.rationale
    attempt.evaluation = evaluation
    attempt.status = AttemptStatus.SUBMITTED
    attempt.finished_at = utc_now()
    session.commit()
    return attempt


def give_up(session: Session, attempt: ScenarioAttempt) -> ScenarioAttempt:
    _require_open(attempt)
    attempt.status = AttemptStatus.REVEALED
    attempt.finished_at = utc_now()
    session.commit()
    return attempt
