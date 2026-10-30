"""Bundled synthetic datasets that can be loaded from the UI or API."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.sample_data.baseline import generate_baseline
from app.sample_data.detection_lab import generate_detection_lab


@dataclass(frozen=True)
class DatasetDefinition:
    id: str
    name: str
    description: str
    generate: Callable[[], list[dict[str, Any]]]


DATASETS: dict[str, DatasetDefinition] = {
    "baseline": DatasetDefinition(
        id="baseline",
        name="Baseline office activity",
        description=(
            "Three ordinary working days at a fictional company: logons, desktop "
            "applications, routine admin commands, a nightly backup job. Contains "
            "no attack activity; useful for spotting false positives."
        ),
        generate=generate_baseline,
    ),
    "detection-lab": DatasetDefinition(
        id="detection-lab",
        name="Detection lab (labeled)",
        description=(
            "One synthetic day containing activity that each detection rule should "
            "report, next to lookalikes it must not report. Used by the rule tests; "
            "loading it creates the expected alerts."
        ),
        generate=generate_detection_lab,
    ),
}
