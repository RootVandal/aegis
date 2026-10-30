"""Named, documented regular-expression indicators for command lines."""

import re
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Indicator:
    id: str
    description: str
    pattern: re.Pattern[str]
    mitre_id: str | None = None  # only when the indicator alone justifies the mapping

    def search(self, text: str) -> str | None:
        """The matched text, or None."""
        match = self.pattern.search(text)
        return match.group(0) if match else None


def indicator(id: str, description: str, regex: str, mitre_id: str | None = None) -> Indicator:
    return Indicator(id, description, re.compile(regex, re.IGNORECASE), mitre_id)


def matches(indicators: Iterable[Indicator], text: str | None) -> list[tuple[Indicator, str]]:
    if not text:
        return []
    found = []
    for item in indicators:
        hit = item.search(text)
        if hit is not None:
            found.append((item, hit))
    return found
