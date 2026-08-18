from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Protocol, TYPE_CHECKING

from .models import PlannedAction

if TYPE_CHECKING:
    from .benchmark import EpisodeResult
    from .scenarios import Scenario


@dataclass(frozen=True)
class AttackObservation:
    """Minimal attacker feedback retained between adaptive rounds."""

    injection: str
    reward: float | None
    violations: tuple[str, ...]
    plan_changed: bool | None
    behavioral_drift: bool | None
    attack_objective_success: bool | None
    protected: bool


class TargetAgent(Protocol):
    """Model/agent adapter consumed by the VAIS benchmark runner."""

    target_id: str

    def run(
        self,
        scenario: "Scenario",
        injected_content: str | None = None,
    ) -> list[PlannedAction]: ...

    def metadata(self) -> dict[str, str]: ...


class Attacker(Protocol):
    """Stable interface for static, iterative, LLM, and RLVR attackers."""

    attacker_id: str

    def generate(
        self,
        scenario: "Scenario",
        history: tuple[AttackObservation, ...],
    ) -> str: ...

    def observe(self, result: "EpisodeResult") -> None: ...


class ScenarioStaticAttacker:
    """Replay the scenario's deterministic reference injection."""

    attacker_id = "scenario-static"

    def generate(
        self,
        scenario: "Scenario",
        history: tuple[AttackObservation, ...],
    ) -> str:
        del history
        return scenario.attack_text

    def observe(self, result: "EpisodeResult") -> None:
        del result


class ReplayAttacker:
    """Replay a deterministic list of attack candidates in round-robin order."""

    def __init__(self, injections: list[str], attacker_id: str = "replay") -> None:
        if not injections or any(not isinstance(item, str) or not item for item in injections):
            raise ValueError("ReplayAttacker requires at least one non-empty injection")
        self.injections = tuple(injections)
        self.attacker_id = attacker_id
        self._cursor = 0

    def generate(
        self,
        scenario: "Scenario",
        history: tuple[AttackObservation, ...],
    ) -> str:
        del scenario, history
        injection = self.injections[self._cursor % len(self.injections)]
        self._cursor += 1
        return injection

    def observe(self, result: "EpisodeResult") -> None:
        del result


class DeterministicScenarioTarget:
    """A deterministic vulnerable target used to validate benchmark semantics.

    This is intentionally *not* presented as an LLM. It returns the scenario's
    baseline plan on clean input and the scenario's compromised plan whenever
    an injection is present. ``susceptible_scenarios`` can model heterogeneous
    target behavior without introducing probabilistic model calls.
    """

    def __init__(
        self,
        target_id: str = "deterministic-vulnerable",
        susceptible_scenarios: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.target_id = target_id
        self.susceptible_scenarios = (
            None if susceptible_scenarios is None else frozenset(susceptible_scenarios)
        )

    def run(
        self,
        scenario: "Scenario",
        injected_content: str | None = None,
    ) -> list[PlannedAction]:
        if not injected_content:
            return list(scenario.baseline_plan)
        if self.susceptible_scenarios is not None and scenario.id not in self.susceptible_scenarios:
            return list(scenario.baseline_plan)
        return list(scenario.compromised_plan)

    def metadata(self) -> dict[str, str]:
        susceptibility = (
            "all" if self.susceptible_scenarios is None else ",".join(sorted(self.susceptible_scenarios))
        )
        return {
            "adapter": "deterministic_scenario_target",
            "target_id": self.target_id,
            "susceptible_scenarios": susceptibility,
        }


@dataclass(frozen=True)
class AttackCandidate:
    id: str
    scenario_id: str
    text: str
    metadata: dict[str, str]


def load_attack_corpus(path: str | Path) -> tuple[AttackCandidate, ...]:
    """Load a replayable JSONL attack corpus with strict required fields."""

    candidates: list[AttackCandidate] = []
    seen_ids: set[str] = set()
    for line_number, raw_line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"attack corpus line {line_number}: invalid JSON") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"attack corpus line {line_number}: must be a JSON object")
        unknown = set(raw) - {"id", "scenario_id", "text", "metadata"}
        if unknown:
            raise ValueError(
                f"attack corpus line {line_number}: unknown field(s): {', '.join(sorted(unknown))}"
            )
        candidate_id = raw.get("id")
        scenario_id = raw.get("scenario_id")
        text = raw.get("text")
        metadata = raw.get("metadata", {})
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise ValueError(f"attack corpus line {line_number}: id must be a non-empty string")
        if candidate_id in seen_ids:
            raise ValueError(f"attack corpus line {line_number}: duplicate id '{candidate_id}'")
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise ValueError(
                f"attack corpus line {line_number}: scenario_id must be a non-empty string"
            )
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"attack corpus line {line_number}: text must be a non-empty string")
        if not isinstance(metadata, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in metadata.items()
        ):
            raise ValueError(
                f"attack corpus line {line_number}: metadata must be a string-to-string mapping"
            )
        seen_ids.add(candidate_id)
        candidates.append(
            AttackCandidate(
                id=candidate_id,
                scenario_id=scenario_id,
                text=text,
                metadata=dict(metadata),
            )
        )
    if not candidates:
        raise ValueError("attack corpus must contain at least one candidate")
    return tuple(candidates)


class CorpusEntryAttacker:
    """Replay exactly one corpus candidate against its declared scenario.

    v0.6 uses one attacker instance per corpus row so every static candidate is
    evaluated exactly once per target/mode instead of round-robin sampling only
    the first candidate for each scenario.
    """

    def __init__(self, candidate: AttackCandidate) -> None:
        self.candidate = candidate
        self.attacker_id = f"corpus:{candidate.id}"

    def supports_scenario(self, scenario: "Scenario") -> bool:
        return scenario.id == self.candidate.scenario_id

    def generate(
        self,
        scenario: "Scenario",
        history: tuple[AttackObservation, ...],
    ) -> str:
        del history
        if not self.supports_scenario(scenario):
            raise ValueError(
                f"candidate '{self.candidate.id}' belongs to scenario "
                f"'{self.candidate.scenario_id}', not '{scenario.id}'"
            )
        return self.candidate.text

    def metadata(self) -> dict[str, str]:
        return {
            "attack_id": self.candidate.id,
            "scenario_id": self.candidate.scenario_id,
            **self.candidate.metadata,
        }

    def observe(self, result: "EpisodeResult") -> None:
        del result


def corpus_entry_attackers(
    candidates: tuple[AttackCandidate, ...] | list[AttackCandidate],
) -> tuple[CorpusEntryAttacker, ...]:
    """Expand a corpus into one scenario-scoped attacker per candidate."""

    return tuple(CorpusEntryAttacker(candidate) for candidate in candidates)


class CorpusAttacker:
    """Replay scenario-specific candidates from a validated attack corpus."""

    def __init__(
        self,
        candidates: tuple[AttackCandidate, ...] | list[AttackCandidate],
        attacker_id: str = "corpus-replay",
    ) -> None:
        if not candidates:
            raise ValueError("CorpusAttacker requires at least one candidate")
        by_scenario: dict[str, list[AttackCandidate]] = {}
        for candidate in candidates:
            by_scenario.setdefault(candidate.scenario_id, []).append(candidate)
        self._by_scenario = {
            scenario_id: tuple(items) for scenario_id, items in by_scenario.items()
        }
        self._cursor: dict[str, int] = {}
        self.attacker_id = attacker_id

    def generate(
        self,
        scenario: "Scenario",
        history: tuple[AttackObservation, ...],
    ) -> str:
        del history
        candidates = self._by_scenario.get(scenario.id)
        if not candidates:
            raise ValueError(f"attack corpus has no candidate for scenario '{scenario.id}'")
        cursor = self._cursor.get(scenario.id, 0)
        candidate = candidates[cursor % len(candidates)]
        self._cursor[scenario.id] = cursor + 1
        return candidate.text

    def observe(self, result: "EpisodeResult") -> None:
        del result
