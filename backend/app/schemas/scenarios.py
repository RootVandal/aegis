"""Scenario Lab request/response models.

Public models deliberately have no fields for correct answers, the evidence
key or the model reasoning. Those exist only in ``SolutionOut``, which the
API attaches to an attempt after it is closed. Hiding is structural, not a
front-end convention.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AttemptStatus
from app.schemas.detection import AlertSummary


class AttemptRef(BaseModel):
    id: int
    status: AttemptStatus
    completed: bool | None = Field(description="Graded result; null if not submitted.")


class ScenarioSummary(BaseModel):
    id: str
    title: str
    difficulty: Literal["beginner", "intermediate", "advanced"]
    summary: str
    relevant_rules: list[str]
    event_count: int
    loaded_events: int
    attempt_count: int
    completed: bool = Field(description="True if any attempt met every objective.")
    latest_attempt: AttemptRef | None


class OptionOut(BaseModel):
    id: str
    text: str


class QuestionOut(BaseModel):
    id: str
    prompt: str
    options: list[OptionOut]


class ScenarioDetail(ScenarioSummary):
    scenario_tag: str = Field(description="scenario_id value on this scenario's events.")
    context: str
    objectives: list[str]
    hint_count: int
    questions: list[QuestionOut]
    alerts: list[AlertSummary] = Field(description="Alerts raised from this scenario's events.")


class RequiredEvidenceOut(BaseModel):
    description: str
    event_ids: list[str]


class DecoyOut(BaseModel):
    event_ids: list[str]
    why: str


class AnswerKeyOut(BaseModel):
    correct: str
    explanation: str


class SolutionOut(BaseModel):
    reasoning: list[str]
    false_positive_discussion: list[str]
    required_evidence: list[RequiredEvidenceOut]
    supporting_evidence: list[str]
    decoys: list[DecoyOut]
    answers: dict[str, AnswerKeyOut]


class AttemptOut(BaseModel):
    id: int
    scenario_id: str
    status: AttemptStatus
    started_at: datetime
    finished_at: datetime | None
    elapsed_seconds: float = Field(description="Informational only; never used in grading.")
    hints: list[str] = Field(description="Hints revealed so far, in order.")
    hints_remaining: int
    answers: dict[str, str]
    evidence_event_ids: list[str]
    rationale: str
    evaluation: dict[str, Any] | None
    solution: SolutionOut | None = Field(description="Only present once the attempt is closed.")


class SubmissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answers: dict[str, str] = Field(default_factory=dict, max_length=20)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=100)
    rationale: str = Field(default="", max_length=10_000)
