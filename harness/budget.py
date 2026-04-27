"""Budget accounting - turn count, USD spend, per-target tool calls."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .engagement import Budget


@dataclass
class BudgetLedger:
    spec: Budget
    turns: int = 0
    usd: float = 0.0
    tool_calls_per_target: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )

    def record_turn(self) -> None:
        self.turns += 1

    def record_cost(self, usd: float) -> None:
        if usd < 0:
            raise ValueError("usd cost must be non-negative")
        self.usd += usd

    def record_tool_call(self, target: str) -> None:
        self.tool_calls_per_target[target] += 1

    def exceeded(self, target: str | None = None) -> str | None:
        if self.turns >= self.spec.max_turns:
            return f"max_turns reached ({self.turns}/{self.spec.max_turns})"
        if self.usd >= self.spec.max_usd:
            return f"max_usd reached (${self.usd:.2f}/${self.spec.max_usd:.2f})"
        if target is not None:
            n = self.tool_calls_per_target[target]
            if n >= self.spec.max_tool_calls_per_target:
                return (
                    f"max_tool_calls_per_target reached for {target} "
                    f"({n}/{self.spec.max_tool_calls_per_target})"
                )
        return None
