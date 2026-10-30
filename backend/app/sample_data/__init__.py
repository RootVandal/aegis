"""Bundled synthetic datasets that can be loaded from the UI or API."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.sample_data.baseline import generate_baseline


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
}
