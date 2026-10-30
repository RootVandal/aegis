"""Detection evaluation lab: labeled suite, runs and comparisons."""

from collections import Counter
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.base import utc_now
from app.db.session import get_db
from app.detection.engine import RuleConfig
from app.detection.registry import RULES
from app.evaluation.runner import evaluate
from app.evaluation.suite import CASES, CATEGORIES, SUITE_ID, SUITE_NAME, dataset_version
from app.models import EvaluationRun
from app.services.detection import rule_settings

router = APIRouter(prefix="/evaluation", tags=["evaluation"])
DB = Annotated[Session, Depends(get_db)]

METRIC_DEFINITIONS = {
    "tp": "Behavior present and the rule fired.",
    "fp": "Behavior absent but the rule fired.",
    "fn": "Behavior present but the rule did not fire.",
    "tn": "Behavior absent and the rule did not fire.",
    "precision": "TP / (TP + FP). Undefined (null) when the rule never fired.",
    "recall": "TP / (TP + FN). Undefined (null) when no case contains the behavior.",
    "f1": "2·TP / (2·TP + FP + FN). Undefined only when TP, FP and FN are all zero.",
    "micro": "Counts summed over all rules, then the ratios computed once.",
    "macro": "Mean of the per-rule values that are defined; `rules` says how many.",
}


class DatasetOut(BaseModel):
    id: str
    name: str
    version: str
    case_count: int
    categories: dict[str, int]
    metric_definitions: dict[str, str]


class CaseOut(BaseModel):
    id: str
    title: str
    category: str
    description: str
    expected: list[str] = Field(description="Rules whose target behavior is present.")
    records: list[dict[str, Any]]
    expected_rejected: int


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str = SUITE_ID
    settings: Literal["current", "defaults"] = Field(
        default="current",
        description="'current' uses the rule parameters configured in AEGIS; "
        "'defaults' ignores all overrides.",
    )


class RunSummary(BaseModel):
    id: int
    created_at: datetime
    dataset_id: str
    dataset_version: str
    settings_source: str
    micro: dict[str, float | int | None]
    input_handling_ok: bool


class RunDetail(RunSummary):
    rules: dict[str, Any]
    results: dict[str, Any]
    comparison: dict[str, Any] | None = Field(
        description="Differences from the previous run on the same dataset, if any."
    )


def _require_suite(dataset_id: str) -> None:
    if dataset_id != SUITE_ID:
        raise AppError(404, "dataset_not_found", f"No evaluation dataset named {dataset_id!r}.")


@router.get("/datasets", response_model=list[DatasetOut], summary="Labeled test datasets")
def list_datasets() -> list[DatasetOut]:
    counts = Counter(case.category for case in CASES)
    return [
        DatasetOut(
            id=SUITE_ID,
            name=SUITE_NAME,
            version=dataset_version(),
            case_count=len(CASES),
            categories={category: counts.get(category, 0) for category in CATEGORIES},
            metric_definitions=METRIC_DEFINITIONS,
        )
    ]


@router.get("/datasets/{dataset_id}/cases", response_model=list[CaseOut], summary="Test cases")
def list_cases(dataset_id: str) -> list[CaseOut]:
    _require_suite(dataset_id)
    return [
        CaseOut(
            id=c.id,
            title=c.title,
            category=c.category,
            description=c.description,
            expected=sorted(c.expected),
            records=[dict(r) for r in c.records],
            expected_rejected=c.expected_rejected,
        )
        for c in CASES
    ]


def _summary(run: EvaluationRun) -> RunSummary:
    return RunSummary(
        id=run.id,
        created_at=run.created_at,
        dataset_id=run.dataset_id,
        dataset_version=run.dataset_version,
        settings_source=run.settings_source,
        micro=run.results["totals"]["micro"],
        input_handling_ok=run.results["input_handling_ok"],
    )


def _compare(run: EvaluationRun, previous: EvaluationRun | None) -> dict[str, Any] | None:
    if previous is None:
        return None
    rules: dict[str, Any] = {}
    for rule_id, now in run.results["per_rule"].items():
        before = previous.results["per_rule"].get(rule_id)
        if before is None:
            continue
        delta = {k: now[k] - before[k] for k in ("tp", "fp", "fn", "tn")}
        version_before = previous.rules.get(rule_id, {}).get("version")
        version_now = run.rules.get(rule_id, {}).get("version")
        params_changed = previous.rules.get(rule_id, {}).get("params") != run.rules.get(
            rule_id, {}
        ).get("params")
        if any(delta.values()) or version_before != version_now or params_changed:
            rules[rule_id] = {
                "delta": delta,
                "version": [version_before, version_now],
                "params_changed": params_changed,
            }
    return {
        "previous_run_id": previous.id,
        "dataset_changed": previous.dataset_version != run.dataset_version,
        "rules": rules,
    }


def _previous(db: Session, run: EvaluationRun) -> EvaluationRun | None:
    return db.scalar(
        select(EvaluationRun)
        .where(EvaluationRun.dataset_id == run.dataset_id, EvaluationRun.id < run.id)
        .order_by(EvaluationRun.id.desc())
        .limit(1)
    )


def _detail(db: Session, run: EvaluationRun) -> RunDetail:
    return RunDetail(
        **_summary(run).model_dump(),
        rules=run.rules,
        results=run.results,
        comparison=_compare(run, _previous(db, run)),
    )


@router.post("/runs", response_model=RunDetail, status_code=201, summary="Run the suite")
def start_run(body: RunRequest, db: DB) -> RunDetail:
    """Executes every rule on every labeled case now and stores the result.

    Every rule is evaluated, including disabled ones: the question is how good
    the rule is, not whether it is switched on.
    """
    _require_suite(body.dataset_id)
    settings = rule_settings(db) if body.settings == "current" else {}
    configs = [RuleConfig(rule, settings[rule.id].params if rule.id in settings else {})
               for rule in RULES]  # fmt: skip
    results = evaluate(configs)
    for rule_id, info in results["rules"].items():
        info["enabled"] = settings[rule_id].enabled if rule_id in settings else True
    run = EvaluationRun(
        created_at=utc_now(),
        dataset_id=body.dataset_id,
        dataset_version=dataset_version(),
        settings_source=body.settings,
        rules=results.pop("rules"),
        results=results,
    )
    db.add(run)
    db.commit()
    return _detail(db, run)


@router.get("/runs", response_model=list[RunSummary], summary="Previous runs")
def list_runs(db: DB, limit: Annotated[int, Query(ge=1, le=100)] = 20) -> list[RunSummary]:
    runs = db.scalars(select(EvaluationRun).order_by(EvaluationRun.id.desc()).limit(limit))
    return [_summary(run) for run in runs]


@router.get("/runs/{run_id}", response_model=RunDetail, summary="Run results")
def get_run(run_id: int, db: DB) -> RunDetail:
    run = db.get(EvaluationRun, run_id)
    if run is None:
        raise AppError(404, "run_not_found", f"No evaluation run with ID {run_id}.")
    return _detail(db, run)
