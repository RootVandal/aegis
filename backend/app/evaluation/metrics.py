"""Detection quality metrics with explicit handling of undefined values.

For one rule over a labeled test suite:

* TP: the behavior is present (label) and the rule fired.
* FP: the behavior is absent and the rule fired.
* FN: the behavior is present and the rule did not fire.
* TN: the behavior is absent and the rule did not fire.

precision = TP / (TP + FP)   "When the rule fires, how often is it right?"
recall    = TP / (TP + FN)   "Of the cases it should catch, how many does it?"
F1        = 2·TP / (2·TP + FP + FN)   (harmonic mean of the two)

A metric whose denominator is zero is **undefined** and reported as None,
never as 0 or 1. A rule that never fired has no precision: claiming 100%
or 0% would both be invented numbers. F1 uses the count form, which is
defined whenever there is at least one TP, FP or FN. It can therefore be 0
while precision is undefined (the rule never fired but missed cases).
"""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def __add__(self, other: "Counts") -> "Counts":
        return Counts(
            self.tp + other.tp, self.fp + other.fp, self.fn + other.fn, self.tn + other.tn
        )

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def precision(c: Counts) -> float | None:
    return ratio(c.tp, c.tp + c.fp)


def recall(c: Counts) -> float | None:
    return ratio(c.tp, c.tp + c.fn)


def f1(c: Counts) -> float | None:
    return ratio(2 * c.tp, 2 * c.tp + c.fp + c.fn)


def summarize(c: Counts) -> dict[str, float | int | None]:
    return {
        "tp": c.tp,
        "fp": c.fp,
        "fn": c.fn,
        "tn": c.tn,
        "precision": precision(c),
        "recall": recall(c),
        "f1": f1(c),
    }


def macro_average(values: Iterable[float | None]) -> tuple[float | None, int]:
    """Mean over the defined values only, with how many were defined.

    Undefined per-rule values are excluded rather than treated as 0, and the
    count is reported so a reader can see how many rules the average covers.
    """
    defined = [v for v in values if v is not None]
    return (sum(defined) / len(defined) if defined else None), len(defined)
