"""Scenario definitions and evidence-based grading.

A scenario is a self-contained training exercise: a synthetic dataset, a
briefing, questions with one correct answer each, and an *evidence key*:

* **required** evidence: groups of events the analyst must cite (citing any
  one event of a group satisfies it, e.g. one of several beacon connections);
* **supporting** evidence: relevant events that may be cited without penalty;
* **decoys**: events that look suspicious but have a benign explanation.
  Citing one means a conclusion leans on the wrong data, so it is reported.

Grading is deterministic and explainable. It checks conclusions (answers) and
whether they are backed by the right evidence. Free-text reasoning is stored
and shown next to the model answer for self-review, but is NOT auto-graded:
judging prose fairly would need a human or a language model, and AEGIS uses
neither. Time and hints are recorded but never scored.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

Difficulty = Literal["beginner", "intermediate", "advanced"]
MIN_RATIONALE_CHARS = 40


@dataclass(frozen=True)
class Option:
    id: str
    text: str


@dataclass(frozen=True)
class Question:
    id: str
    prompt: str
    options: tuple[Option, ...]
    correct: str
    explanation: str  # revealed only after submission


@dataclass(frozen=True)
class RequiredEvidence:
    description: str
    event_ids: tuple[str, ...]  # citing any one of these satisfies the requirement


@dataclass(frozen=True)
class Decoy:
    event_ids: tuple[str, ...]
    why: str  # the benign explanation, revealed after submission


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    difficulty: Difficulty
    summary: str
    context: str  # the briefing an analyst would receive
    objectives: tuple[str, ...]
    relevant_rules: tuple[str, ...]
    hints: tuple[str, ...]
    questions: tuple[Question, ...]
    required_evidence: tuple[RequiredEvidence, ...]
    supporting_evidence: tuple[str, ...]
    decoys: tuple[Decoy, ...]
    reasoning: tuple[str, ...]  # the intended line of investigation, revealed after
    false_positive_discussion: tuple[str, ...]
    generate: Callable[[], list[dict[str, Any]]] = field(compare=False)

    @property
    def scenario_tag(self) -> str:
        """Value of ``scenario_id`` on every event of this scenario."""
        return f"lab-{self.id}"


@dataclass(frozen=True)
class GradeInput:
    answers: Mapping[str, str]
    evidence_event_ids: Sequence[str]
    rationale: str


class GradingError(ValueError):
    """The submission does not fit the scenario (unknown question/option/event)."""


def grade(scenario: Scenario, submission: GradeInput, known_event_ids: set[str]) -> dict[str, Any]:
    question_ids = {q.id for q in scenario.questions}
    unknown = set(submission.answers) - question_ids
    if unknown:
        raise GradingError(f"Unknown question(s): {', '.join(sorted(unknown))}.")
    stray = set(submission.evidence_event_ids) - known_event_ids
    if stray:
        raise GradingError(
            "Evidence must come from this scenario's events; not found: "
            + ", ".join(sorted(stray)[:5])
        )

    cited = set(submission.evidence_event_ids)
    questions: list[dict[str, Any]] = []
    for question in scenario.questions:
        answer = submission.answers.get(question.id)
        if answer is not None and answer not in {o.id for o in question.options}:
            raise GradingError(f"Unknown option {answer!r} for question {question.id}.")
        questions.append(
            {
                "id": question.id,
                "prompt": question.prompt,
                "your_answer": answer,
                "correct_answer": question.correct,
                "correct": answer == question.correct,
                "explanation": question.explanation,
            }
        )

    required: list[dict[str, Any]] = [
        {
            "description": item.description,
            "event_ids": list(item.event_ids),
            "cited": bool(cited & set(item.event_ids)),
        }
        for item in scenario.required_evidence
    ]
    decoy_hits = [
        {"event_ids": sorted(cited & set(d.event_ids)), "why": d.why}
        for d in scenario.decoys
        if cited & set(d.event_ids)
    ]
    accounted = (
        {i for item in scenario.required_evidence for i in item.event_ids}
        | set(scenario.supporting_evidence)
        | {i for d in scenario.decoys for i in d.event_ids}
    )
    supporting = sorted(cited & set(scenario.supporting_evidence))
    unrelated = sorted(cited - accounted)

    answered_all = all(q["your_answer"] is not None for q in questions)
    all_correct = all(q["correct"] for q in questions)
    evidence_complete = all(item["cited"] for item in required)
    rationale_ok = len(submission.rationale.strip()) >= MIN_RATIONALE_CHARS
    objectives = [
        {
            "objective": "Answer every question",
            "met": answered_all,
            "detail": f"{sum(q['your_answer'] is not None for q in questions)} of "
            f"{len(questions)} answered.",
        },
        {
            "objective": "Reach correct conclusions",
            "met": all_correct,
            "detail": f"{sum(q['correct'] for q in questions)} of {len(questions)} correct.",
        },
        {
            "objective": "Cite the key evidence",
            "met": evidence_complete,
            "detail": f"{sum(r['cited'] for r in required)} of {len(required)} required "
            "evidence items cited.",
        },
        {
            "objective": "Avoid misleading evidence",
            "met": not decoy_hits,
            "detail": "No benign lookalike cited."
            if not decoy_hits
            else f"{len(decoy_hits)} benign lookalike(s) cited as evidence.",
        },
        {
            "objective": "Explain the reasoning",
            "met": rationale_ok,
            "detail": f"Written rationale of at least {MIN_RATIONALE_CHARS} characters "
            "(stored for self-review; not auto-graded).",
        },
    ]
    return {
        "completed": all(o["met"] for o in objectives),
        "objectives": objectives,
        "questions": questions,
        "evidence": {
            "required": required,
            "decoys_cited": decoy_hits,
            "supporting_cited": supporting,
            "unrelated_cited": unrelated,
        },
    }
