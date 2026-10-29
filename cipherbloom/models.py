from __future__ import annotations

from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str = ""
    line: int = 0
    why: str = ""
    fix: str = ""
    snippet: str = ""
    category: str = "code"

    def to_dict(self):
        return asdict(self)

    def location(self):
        if not self.file:
            return "-"
        return "%s:%d" % (self.file, self.line) if self.line else self.file


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line, f.rule),
    )


def score(findings):
    """Heuristic 0-100 health score. It is NOT a guarantee of safety."""
    total = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, 100 - total)
