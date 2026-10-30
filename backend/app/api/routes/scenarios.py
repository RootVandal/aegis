"""Scenario Lab: list, start, hint, submit, reveal."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.routes.alerts import alert_summary
from app.db.base import utc_now
from app.db.session import get_db
from app.models import ScenarioAttempt
from app.models.enums import AttemptStatus
from app.scenarios import service
from app.scenarios.catalog import SCENARIOS
from app.scenarios.model import GradeInput, Scenario
from app.schemas.scenarios import (
    AnswerKeyOut,
    AttemptOut,
    AttemptRef,
    DecoyOut,
    OptionOut,
    QuestionOut,
    RequiredEvidenceOut,
    ScenarioDetail,
    ScenarioSummary,
    SolutionOut,
    SubmissionIn,
)

router = APIRouter(tags=["scenarios"])
DB = Annotated[Session, Depends(get_db)]


def _summary(db: Session, scenario: Scenario) -> ScenarioSummary:
    attempts = service.attempts_for(db, scenario.id)
    latest = attempts[0] if attempts else None
    return ScenarioSummary(
        id=scenario.id,
        title=scenario.title,
        difficulty=scenario.difficulty,
        summary=scenario.summary,
        relevant_rules=list(scenario.relevant_rules),
        event_count=len(scenario.generate()),
        loaded_events=len(service.loaded_event_ids(db, scenario)),
        attempt_count=len(attempts),
        completed=any(a.evaluation and a.evaluation.get("completed") for a in attempts),
        latest_attempt=AttemptRef(
            id=latest.id,
            status=latest.status,
            completed=latest.evaluation.get("completed") if latest.evaluation else None,
        )
        if latest
        else None,
    )


def _attempt(attempt: ScenarioAttempt) -> AttemptOut:
    scenario = service.get_scenario(attempt.scenario_id)
    closed = attempt.status != AttemptStatus.IN_PROGRESS
    end = attempt.finished_at or utc_now()
    solution = (
        SolutionOut(
            reasoning=list(scenario.reasoning),
            false_positive_discussion=list(scenario.false_positive_discussion),
            required_evidence=[
                RequiredEvidenceOut(description=r.description, event_ids=list(r.event_ids))
                for r in scenario.required_evidence
            ],
            supporting_evidence=list(scenario.supporting_evidence),
            decoys=[DecoyOut(event_ids=list(d.event_ids), why=d.why) for d in scenario.decoys],
            answers={
                q.id: AnswerKeyOut(correct=q.correct, explanation=q.explanation)
                for q in scenario.questions
            },
        )
        if closed
        else None
    )
    return AttemptOut(
        id=attempt.id,
        scenario_id=attempt.scenario_id,
        status=attempt.status,
        started_at=attempt.started_at,
        finished_at=attempt.finished_at,
        elapsed_seconds=(end - attempt.started_at).total_seconds(),
        hints=list(scenario.hints[: attempt.hints_used]),
        hints_remaining=len(scenario.hints) - attempt.hints_used,
        answers=attempt.answers,
        evidence_event_ids=attempt.evidence_event_ids,
        rationale=attempt.rationale,
        evaluation=attempt.evaluation,
        solution=solution,
    )


@router.get("/scenarios", response_model=list[ScenarioSummary], summary="Training scenarios")
def list_scenarios(db: DB) -> list[ScenarioSummary]:
    return [_summary(db, scenario) for scenario in SCENARIOS.values()]


@router.get("/scenarios/{scenario_id}", response_model=ScenarioDetail, summary="Scenario briefing")
def scenario_detail(scenario_id: str, db: DB) -> ScenarioDetail:
    """The briefing and questions. Answers, the evidence key and the model
    reasoning are not part of this response."""
    scenario = service.get_scenario(scenario_id)
    return ScenarioDetail(
        **_summary(db, scenario).model_dump(),
        scenario_tag=scenario.scenario_tag,
        context=scenario.context,
        objectives=list(scenario.objectives),
        hint_count=len(scenario.hints),
        questions=[
            QuestionOut(
                id=q.id,
                prompt=q.prompt,
                options=[OptionOut(id=o.id, text=o.text) for o in q.options],
            )
            for q in scenario.questions
        ],
        alerts=[alert_summary(a) for a in service.scenario_alerts(db, scenario)],
    )


@router.get(
    "/scenarios/{scenario_id}/attempts", response_model=list[AttemptOut], summary="Attempt history"
)
def scenario_attempts(scenario_id: str, db: DB) -> list[AttemptOut]:
    service.get_scenario(scenario_id)
    return [_attempt(a) for a in service.attempts_for(db, scenario_id)]


@router.post(
    "/scenarios/{scenario_id}/attempts",
    response_model=AttemptOut,
    status_code=201,
    summary="Start a scenario attempt",
)
def start_attempt(scenario_id: str, db: DB) -> AttemptOut:
    """Loads the scenario's synthetic events if needed (detection runs on them)
    and opens a new attempt. Earlier attempts are kept."""
    return _attempt(service.start_attempt(db, service.get_scenario(scenario_id)))


@router.get("/scenario-attempts/{attempt_id}", response_model=AttemptOut, summary="Attempt state")
def get_attempt(attempt_id: int, db: DB) -> AttemptOut:
    return _attempt(service.get_attempt(db, attempt_id))


@router.post(
    "/scenario-attempts/{attempt_id}/hints", response_model=AttemptOut, summary="Reveal next hint"
)
def reveal_hint(attempt_id: int, db: DB) -> AttemptOut:
    return _attempt(service.reveal_hint(db, service.get_attempt(db, attempt_id)))


@router.post(
    "/scenario-attempts/{attempt_id}/submit",
    response_model=AttemptOut,
    summary="Submit for grading",
)
def submit_attempt(attempt_id: int, body: SubmissionIn, db: DB) -> AttemptOut:
    """Grades conclusions and cited evidence; closes the attempt and unlocks the
    model reasoning. Time and hints are not part of the grade."""
    attempt = service.submit(
        db,
        service.get_attempt(db, attempt_id),
        GradeInput(body.answers, body.evidence_event_ids, body.rationale),
    )
    return _attempt(attempt)


@router.post(
    "/scenario-attempts/{attempt_id}/reveal",
    response_model=AttemptOut,
    summary="Show the explanation without submitting",
)
def reveal(attempt_id: int, db: DB) -> AttemptOut:
    return _attempt(service.give_up(db, service.get_attempt(db, attempt_id)))
