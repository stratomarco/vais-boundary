from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable

import yaml


_SCHEMA_VERSION = "vais-research-evidence-v1"
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules"}
_RELEVANT_SUFFIXES = {".json", ".jsonl", ".yaml", ".yml", ".md", ".toml", ".txt", ".zip", ".whl", ".pdf", ".docx", ".py"}


@dataclass(frozen=True)
class ResearchBuildResult:
    database: Path
    artifacts: int
    experiments: int
    observations: int
    claims: int
    findings: int
    decisions: int
    limitations: int
    sources: int
    hypotheses: int
    evidence_links: int
    resolved_evidence_links: int
    roots: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _SCHEMA_VERSION,
            "database": str(self.database),
            "artifacts": self.artifacts,
            "experiments": self.experiments,
            "observations": self.observations,
            "claims": self.claims,
            "findings": self.findings,
            "decisions": self.decisions,
            "limitations": self.limitations,
            "sources": self.sources,
            "hypotheses": self.hypotheses,
            "evidence_links": self.evidence_links,
            "resolved_evidence_links": self.resolved_evidence_links,
            "roots": list(self.roots),
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _artifact_id(path: Path, digest: str) -> str:
    path_digest = hashlib.sha256(str(path).encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"ART-{digest[:16]}-{path_digest}"


def _normalize_version(text: str | None) -> str | None:
    if not text:
        return None
    m = re.search(r"(?i)(?:^|[^0-9])v?(0\.\d+(?:\.\d+)?)", text)
    if m:
        version = m.group(1)
        if version.count(".") == 1:
            version += ".0"
        return version
    m = re.search(r"(?i)\bv(\d{2,3})\b", text)
    if m:
        digits = m.group(1)
        if len(digits) == 2:
            if digits.startswith("0"):
                return f"0.{int(digits[1])}.0"
            return f"0.{int(digits[0])}.{int(digits[1])}"
        if len(digits) == 3:
            if digits.startswith("01"):
                return f"0.{int(digits[1:])}.0"
            return f"0.{int(digits[:-1])}.{int(digits[-1])}"
    return None


def _detect_root_version(root: Path) -> str | None:
    if root.is_file():
        return _normalize_version(root.name)
    if not root.exists() or not root.is_dir():
        return None
    candidates = [root / "pyproject.toml"]
    try:
        candidates.extend(path for path in root.glob("*/pyproject.toml"))
        candidates.extend(path for path in root.glob("*/*/pyproject.toml"))
    except OSError:
        pass
    for path in candidates:
        if not path.exists():
            continue
        try:
            import tomllib
            with path.open("rb") as fh:
                raw = tomllib.load(fh)
            version = raw.get("project", {}).get("version")
            if isinstance(version, str) and version.strip():
                return version.strip()
        except Exception:
            continue
    version_files = [root / "src" / "vais" / "_version.py"]
    try:
        version_files.extend(path for path in root.glob("*/src/vais/_version.py"))
    except OSError:
        pass
    for path in version_files:
        if path.exists():
            try:
                match = re.search(r'__version__\s*=\s*["\']([^"\']+)', path.read_text(encoding="utf-8"))
                if match:
                    return match.group(1)
            except OSError:
                pass
    return _normalize_version(root.name)


def _classify(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".jsonl"):
        if "rlvr" in name:
            return "rlvr_trajectory"
        return "episode_jsonl"
    if name.endswith("summary.json") or "summary" in name and name.endswith(".json"):
        return "summary_json"
    if "audit" in name and name.endswith(".json"):
        return "audit_json"
    if "sha256" in name:
        return "checksums"
    if name == "changelog.md":
        return "changelog"
    if name == "pyproject.toml":
        return "project_metadata"
    if path.suffix.lower() == ".zip":
        return "source_archive"
    if path.suffix.lower() == ".whl":
        return "wheel"
    if path.suffix.lower() in {".pdf", ".docx", ".py"}:
        return "research_source"
    return "document"


def _iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in _RELEVANT_SUFFIXES:
            yield root
        return
    if not root.exists():
        return
    for current, dirs, files in __import__("os").walk(root):
        current_path = Path(current)
        if current_path.name in {"evidence", "db"} and current_path.parent.name == "research":
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            path = current_path / name
            if path.suffix.lower() in _RELEVANT_SUFFIXES:
                yield path


def _read_yaml_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return []
    if isinstance(raw, dict):
        for key in ("items", "claims", "findings", "decisions", "limitations", "terms", "sources", "hypotheses"):
            if isinstance(raw.get(key), list):
                return [item for item in raw[key] if isinstance(item, dict)]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    raise ValueError(f"expected list-style YAML in {path}")


def _target_id(record: dict[str, Any]) -> str | None:
    if isinstance(record.get("target_id"), str):
        return record["target_id"]
    target = record.get("target")
    if isinstance(target, dict) and isinstance(target.get("id"), str):
        return target["id"]
    return None


def _framework_version(record: dict[str, Any], path: Path) -> str | None:
    value = record.get("framework_version")
    if isinstance(value, str):
        return value
    return _normalize_version(path.name) or _normalize_version(str(path.parent))


def _adaptive_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    evaluable = [r for r in rows if r.get("reward_evaluated") is True]
    violations = [r for r in evaluable if r.get("terminal_security_reward") == 1.0 or r.get("protected_violation") is True]
    added = [r for r in evaluable if isinstance(r.get("pair_delta"), dict) and bool(r["pair_delta"].get("added_security_events"))]
    objective = [r for r in evaluable if isinstance(r.get("protected_result"), dict) and r["protected_result"].get("attack_objective_success") is True]
    utility = [r for r in evaluable if isinstance(r.get("protected_result"), dict) and r["protected_result"].get("workflow_utility_success") is True]
    target_fail = [r for r in rows if isinstance(r.get("protected_result"), dict) and r["protected_result"].get("target_failure") is True]
    off_objective = [r for r in added if not (isinstance(r.get("protected_result"), dict) and r["protected_result"].get("attack_objective_success") is True)]
    paired = {"success_success": 0, "success_failure": 0, "failure_success": 0, "failure_failure": 0, "unavailable": 0}
    for r in rows:
        c = r.get("control_result")
        p = r.get("protected_result")
        if not isinstance(c, dict) or not isinstance(p, dict) or c.get("target_failure") or p.get("target_failure"):
            paired["unavailable"] += 1
            continue
        cu = c.get("workflow_utility_success") is True
        pu = p.get("workflow_utility_success") is True
        paired[("success_" if cu else "failure_") + ("success" if pu else "failure")] += 1
    return {
        "episodes": len(rows),
        "evaluable_episodes": len(evaluable),
        "protected_invariant_violations": len(violations),
        "attack_added_security_event_episodes": len(added),
        "attack_objective_success_episodes": len(objective),
        "off_objective_security_event_episodes": len(off_objective),
        "protected_workflow_utility_successes": len(utility),
        "target_failure_episodes": len(target_fail),
        "paired_utility": paired,
    }


def _reference_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [r for r in rows if not r.get("target_failure")]
    attacked = [r for r in rows if r.get("condition") == "attack" or r.get("attacked") is True]
    valid_attacked = [r for r in attacked if not r.get("target_failure")]
    return {
        "episodes": len(rows),
        "evaluable_episodes": len(valid),
        "attack_episodes": len(attacked),
        "evaluable_attack_episodes": len(valid_attacked),
        "security_violation_episodes": sum(r.get("security_violation") is True for r in valid),
        "security_escalation_episodes": sum(r.get("security_escalation_observed") is True for r in valid_attacked),
        "attack_objective_success_episodes": sum(r.get("attack_objective_success") is True for r in valid_attacked),
        "workflow_utility_successes": sum(r.get("workflow_utility_success") is True for r in valid),
        "target_failure_episodes": sum(r.get("target_failure") is True for r in rows),
    }


def _benchmark_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [r for r in rows if r.get("security_evaluated", True)]
    return {
        "episodes": len(rows),
        "evaluable_episodes": len(evaluated),
        "invariant_violation_episodes": sum(bool(r.get("violations")) for r in evaluated),
        "attack_objective_success_episodes": sum(r.get("attack_objective_success") is True for r in evaluated),
        "plan_changed_episodes": sum(r.get("plan_changed") is True for r in evaluated),
        "security_escalation_episodes": sum(
            isinstance(r.get("behavioral_drift"), dict) and r["behavioral_drift"].get("security_escalation") is True
            for r in evaluated
        ),
        "clean_utility_successes": sum(r.get("clean_utility_success") is True for r in rows),
        "target_failure_episodes": sum(
            (isinstance(r.get("target_status"), dict) and r["target_status"].get("valid") is False)
            or (isinstance(r.get("generation"), dict) and r["generation"].get("candidate", {}).get("status") not in (None, "valid_plan"))
            for r in rows
        ),
    }


def _extract_json_document(path: Path) -> list[dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(raw, dict):
        return []
    by_target = raw.get("by_target")
    if not isinstance(by_target, dict) or not by_target:
        return []
    analysis_version = raw.get("framework_version") if isinstance(raw.get("framework_version"), str) else _normalize_version(path.name)
    if "source_framework_versions" in raw:
        mode = "offline_audit"
    elif raw.get("mode"):
        mode = f"summary:{raw.get('mode')}"
    elif raw.get("reference_system"):
        mode = f"summary:{raw.get('reference_system')}"
    else:
        mode = "summary"
    experiments: list[dict[str, Any]] = []
    for target_id, metrics in sorted(by_target.items()):
        if not isinstance(metrics, dict):
            continue
        payload = dict(metrics)
        if raw.get("overall") is not None:
            payload["overall"] = raw.get("overall")
        if raw.get("source_framework_versions") is not None:
            payload["source_framework_versions"] = raw.get("source_framework_versions")
        if raw.get("reasoning_mode_audit") is not None:
            payload["reasoning_mode_audit"] = raw.get("reasoning_mode_audit")
        eid = f"EXP-{hashlib.sha256((str(path)+str(target_id)+mode).encode()).hexdigest()[:16]}"
        experiments.append({
            "id": eid,
            "framework_version": analysis_version,
            "target_id": str(target_id),
            "mode": mode,
            "source_path": str(path),
            "metrics": payload,
        })
    return experiments


def _extract_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                record = dict(record)
                record["_line"] = line_number
                rows.append(record)
    if not rows:
        return [], []

    groups: dict[tuple[str | None, str | None, str | None], list[dict[str, Any]]] = {}
    for r in rows:
        version = _framework_version(r, path)
        target = _target_id(r)
        if "reward_evaluated" in r and "protected_result" in r:
            mode = "adaptive_verification"
        elif "workflow_id" in r and "trace" in r:
            mode = f"reference_agent:{r.get('mode') or 'unknown'}"
        else:
            mode = str(r.get("mode") or r.get("execution_backend") or "benchmark")
        groups.setdefault((version, target, mode), []).append(r)

    experiments: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for idx, ((version, target, mode), items) in enumerate(groups.items(), 1):
        if mode == "adaptive_verification":
            metrics = _adaptive_metrics(items)
        elif mode.startswith("reference_agent:"):
            metrics = _reference_metrics(items)
        else:
            metrics = _benchmark_metrics(items)
        eid = f"EXP-{hashlib.sha256((str(path)+str(idx)+str(target)+str(mode)).encode()).hexdigest()[:16]}"
        experiments.append({
            "id": eid,
            "framework_version": version,
            "target_id": target,
            "mode": mode,
            "source_path": str(path),
            "metrics": metrics,
        })
        for r in items:
            pr = r.get("protected_result") if isinstance(r.get("protected_result"), dict) else {}
            delta = r.get("pair_delta") if isinstance(r.get("pair_delta"), dict) else {}
            observations.append({
                "id": f"OBS-{hashlib.sha256((eid+str(r.get('_line'))).encode()).hexdigest()[:16]}",
                "experiment_id": eid,
                "source_path": str(path),
                "source_line": r.get("_line"),
                "workflow_id": r.get("workflow_id") or (r.get("scenario") or {}).get("id") if isinstance(r.get("scenario"), dict) else r.get("workflow_id"),
                "episode": r.get("episode"),
                "condition": r.get("condition") or r.get("mode"),
                "reward_evaluated": r.get("reward_evaluated", r.get("security_evaluated")),
                "terminal_reward": r.get("terminal_security_reward"),
                "protected_violation": r.get("protected_violation", r.get("security_violation")),
                "target_failure": pr.get("target_failure", r.get("target_failure")),
                "attack_objective_success": pr.get("attack_objective_success", r.get("attack_objective_success")),
                "workflow_utility_success": pr.get("workflow_utility_success", r.get("workflow_utility_success", r.get("clean_utility_success"))),
                "attack_added_security_events": len(delta.get("added_security_events", [])) if isinstance(delta.get("added_security_events", []), list) else 0,
                "candidate_sha256": (r.get("candidate") or {}).get("content_hash") if isinstance(r.get("candidate"), dict) else r.get("injection_hash"),
            })
    return experiments, observations


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA foreign_keys = ON;
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE artifacts(
            id TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
            kind TEXT NOT NULL, version TEXT, mtime_utc TEXT
        );
        CREATE INDEX idx_artifacts_sha ON artifacts(sha256);
        CREATE INDEX idx_artifacts_version ON artifacts(version);
        CREATE TABLE experiments(
            id TEXT PRIMARY KEY, framework_version TEXT, target_id TEXT, mode TEXT NOT NULL,
            source_path TEXT NOT NULL, metrics_json TEXT NOT NULL
        );
        CREATE INDEX idx_experiments_version ON experiments(framework_version);
        CREATE INDEX idx_experiments_target ON experiments(target_id);
        CREATE TABLE observations(
            id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL, source_path TEXT NOT NULL, source_line INTEGER,
            workflow_id TEXT, episode INTEGER, condition TEXT, reward_evaluated INTEGER, terminal_reward REAL,
            protected_violation INTEGER, target_failure INTEGER, attack_objective_success INTEGER,
            workflow_utility_success INTEGER, attack_added_security_events INTEGER, candidate_sha256 TEXT,
            FOREIGN KEY(experiment_id) REFERENCES experiments(id)
        );
        CREATE TABLE claims(id TEXT PRIMARY KEY, status TEXT, claim TEXT NOT NULL, body_json TEXT NOT NULL);
        CREATE TABLE findings(id TEXT PRIMARY KEY, finding TEXT NOT NULL, body_json TEXT NOT NULL);
        CREATE TABLE decisions(id TEXT PRIMARY KEY, decision TEXT NOT NULL, body_json TEXT NOT NULL);
        CREATE TABLE limitations(id TEXT PRIMARY KEY, limitation TEXT NOT NULL, body_json TEXT NOT NULL);
        CREATE TABLE terminology(id TEXT PRIMARY KEY, term TEXT NOT NULL, definition TEXT NOT NULL, body_json TEXT NOT NULL);
        CREATE TABLE sources(id TEXT PRIMARY KEY, title TEXT NOT NULL, source_type TEXT, body_json TEXT NOT NULL);
        CREATE TABLE hypotheses(id TEXT PRIMARY KEY, status TEXT, hypothesis TEXT NOT NULL, body_json TEXT NOT NULL);
        CREATE TABLE evidence_links(
            owner_type TEXT NOT NULL, owner_id TEXT NOT NULL, evidence_ref TEXT NOT NULL,
            artifact_id TEXT, resolved INTEGER NOT NULL, expected_sha256 TEXT, hash_match INTEGER,
            FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
        );
        CREATE INDEX idx_evidence_links_owner ON evidence_links(owner_type, owner_id);
        """
    )



def discover_history_roots(history_root: str | Path) -> tuple[Path, ...]:
    """Return likely VAIS version directories immediately below a history root.

    This intentionally does not recursively crawl the entire drive. It recognizes
    common VAIS checkout names such as ``vais-v03``, ``vais-v0.10`` and
    ``verifiable-ai-security-v0.9.3``.
    """
    root = Path(history_root)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"history root does not exist or is not a directory: {root}")
    candidates: list[Path] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        name = child.name.lower()
        if re.match(r"^vais-v(?:0\.)?\d+", name) or name.startswith("verifiable-ai-security-v"):
            candidates.append(child)
    return tuple(sorted(candidates, key=lambda item: item.name.lower()))

def build_research_database(
    roots: Iterable[str | Path],
    *,
    research_dir: str | Path = "research",
    database: str | Path | None = None,
) -> ResearchBuildResult:
    roots = tuple(str(Path(root).resolve()) for root in roots)
    rdir = Path(research_dir)
    db = Path(database) if database is not None else rdir / "db" / "vais-research.sqlite"
    db.parent.mkdir(parents=True, exist_ok=True)
    if db.exists():
        db.unlink()

    knowledge_dir = rdir / "knowledge"
    if not knowledge_dir.exists():
        knowledge_dir = Path(__file__).resolve().parent / "data" / "research"
    claims = _read_yaml_list(knowledge_dir / "claims.yaml")
    findings = _read_yaml_list(knowledge_dir / "findings.yaml")
    decisions = _read_yaml_list(knowledge_dir / "decisions.yaml")
    limitations = _read_yaml_list(knowledge_dir / "limitations.yaml")
    terms = _read_yaml_list(knowledge_dir / "terminology.yaml")
    sources = _read_yaml_list(knowledge_dir / "sources.yaml")
    hypotheses = _read_yaml_list(knowledge_dir / "hypotheses.yaml")

    artifacts: list[dict[str, Any]] = []
    experiments: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for root_text in roots:
        root = Path(root_text)
        root_version = _detect_root_version(root)
        for path in _iter_files(root):
            resolved = str(path.resolve())
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            try:
                digest = _sha256(path)
                stat = path.stat()
            except OSError:
                continue
            version = _normalize_version(path.name) or root_version or _normalize_version(str(path.parent))
            artifacts.append({
                "id": _artifact_id(path, digest),
                "path": resolved,
                "sha256": digest,
                "size_bytes": stat.st_size,
                "kind": _classify(path),
                "version": version,
                "mtime_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
            if path.suffix.lower() == ".jsonl" and "rlvr" not in path.name.lower():
                exps, obs = _extract_jsonl(path)
                experiments.extend(exps)
                observations.extend(obs)
            elif path.suffix.lower() == ".json":
                experiments.extend(_extract_json_document(path))

    artifacts_by_name: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        artifacts_by_name.setdefault(Path(artifact["path"]).name.lower(), []).append(artifact)
    evidence_links: list[dict[str, Any]] = []
    for owner_type, items in (("claim", claims), ("finding", findings), ("decision", decisions), ("hypothesis", hypotheses)):
        for item in items:
            refs = item.get("evidence") or []
            if isinstance(refs, str):
                refs = [refs]
            for ref in refs:
                matches = artifacts_by_name.get(Path(str(ref)).name.lower(), [])
                if matches:
                    for artifact in matches:
                        evidence_links.append({"owner_type": owner_type, "owner_id": item["id"], "evidence_ref": str(ref), "artifact_id": artifact["id"], "resolved": 1, "expected_sha256": None, "hash_match": None})
                else:
                    evidence_links.append({"owner_type": owner_type, "owner_id": item["id"], "evidence_ref": str(ref), "artifact_id": None, "resolved": 0, "expected_sha256": None, "hash_match": None})
    for item in sources:
        ref = item.get("artifact_name")
        if not ref:
            continue
        matches = artifacts_by_name.get(Path(str(ref)).name.lower(), [])
        expected_sha = item.get("sha256")
        if matches:
            for artifact in matches:
                hash_match = None if expected_sha is None else artifact["sha256"] == expected_sha
                evidence_links.append({
                    "owner_type": "source", "owner_id": item["id"], "evidence_ref": str(ref),
                    "artifact_id": artifact["id"], "resolved": 1 if hash_match is not False else 0,
                    "expected_sha256": expected_sha, "hash_match": None if hash_match is None else int(hash_match),
                })
        else:
            evidence_links.append({
                "owner_type": "source", "owner_id": item["id"], "evidence_ref": str(ref),
                "artifact_id": None, "resolved": 0, "expected_sha256": expected_sha, "hash_match": None,
            })

    with sqlite3.connect(db) as conn:
        _create_schema(conn)
        conn.executemany("INSERT INTO meta(key,value) VALUES(?,?)", [
            ("schema", _SCHEMA_VERSION), ("built_at", _now()), ("roots", json.dumps(list(roots)))
        ])
        conn.executemany(
            "INSERT INTO artifacts VALUES(:id,:path,:sha256,:size_bytes,:kind,:version,:mtime_utc)", artifacts
        )
        conn.executemany(
            "INSERT INTO experiments VALUES(:id,:framework_version,:target_id,:mode,:source_path,:metrics_json)",
            [{**e, "metrics_json": json.dumps(e["metrics"], sort_keys=True)} for e in experiments],
        )
        conn.executemany(
            """INSERT INTO observations VALUES(
            :id,:experiment_id,:source_path,:source_line,:workflow_id,:episode,:condition,:reward_evaluated,
            :terminal_reward,:protected_violation,:target_failure,:attack_objective_success,
            :workflow_utility_success,:attack_added_security_events,:candidate_sha256)""",
            observations,
        )
        for table, items, text_field in (
            ("claims", claims, "claim"), ("findings", findings, "finding"),
            ("decisions", decisions, "decision"), ("limitations", limitations, "limitation")
        ):
            conn.executemany(
                f"INSERT INTO {table}(id,{text_field}," + ("status," if table == "claims" else "") + "body_json) VALUES(" +
                (":id,:claim,:status,:body_json)" if table == "claims" else f":id,:{text_field},:body_json)"),
                [{**item, "body_json": json.dumps(item, sort_keys=True, default=str)} for item in items],
            )
        conn.executemany(
            "INSERT INTO terminology(id,term,definition,body_json) VALUES(:id,:term,:definition,:body_json)",
            [{**item, "body_json": json.dumps(item, sort_keys=True, default=str)} for item in terms],
        )
        conn.executemany(
            "INSERT INTO sources(id,title,source_type,body_json) VALUES(:id,:title,:source_type,:body_json)",
            [{**item, "source_type": item.get("source_type"), "body_json": json.dumps(item, sort_keys=True, default=str)} for item in sources],
        )
        conn.executemany(
            "INSERT INTO hypotheses(id,status,hypothesis,body_json) VALUES(:id,:status,:hypothesis,:body_json)",
            [{**item, "status": item.get("status"), "body_json": json.dumps(item, sort_keys=True, default=str)} for item in hypotheses],
        )
        conn.executemany(
            "INSERT INTO evidence_links(owner_type,owner_id,evidence_ref,artifact_id,resolved,expected_sha256,hash_match) VALUES(:owner_type,:owner_id,:evidence_ref,:artifact_id,:resolved,:expected_sha256,:hash_match)",
            evidence_links,
        )
        conn.commit()

    evidence_dir = rdir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(evidence_dir / "artifact-index.jsonl", artifacts)
    _write_jsonl(evidence_dir / "experiment-index.jsonl", experiments)
    _write_jsonl(evidence_dir / "observation-index.jsonl", observations)
    _write_jsonl(evidence_dir / "claim-evidence-links.jsonl", evidence_links)
    manifest = {
        "schema": _SCHEMA_VERSION,
        "built_at": _now(),
        "roots": list(roots),
        "database": str(db),
        "counts": {
            "artifacts": len(artifacts), "experiments": len(experiments), "observations": len(observations),
            "claims": len(claims), "findings": len(findings), "decisions": len(decisions), "limitations": len(limitations), "sources": len(sources), "hypotheses": len(hypotheses),
            "evidence_links": len(evidence_links), "resolved_evidence_links": sum(item["resolved"] for item in evidence_links),
        },
    }
    (evidence_dir / "build-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ResearchBuildResult(
        db, len(artifacts), len(experiments), len(observations), len(claims), len(findings),
        len(decisions), len(limitations), len(sources), len(hypotheses), len(evidence_links),
        sum(item["resolved"] for item in evidence_links), roots
    )


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def _content_inventory(conn: sqlite3.Connection) -> dict[str, int]:
    artifact_instances = conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    unique_artifact_contents = conn.execute("SELECT COUNT(DISTINCT sha256) FROM artifacts").fetchone()[0]
    duplicate_artifact_groups = conn.execute(
        "SELECT COUNT(*) FROM (SELECT sha256 FROM artifacts GROUP BY sha256 HAVING COUNT(*) > 1)"
    ).fetchone()[0]
    experiment_records = conn.execute("SELECT COUNT(*) FROM experiments").fetchone()[0]
    content_addressed_experiments = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT a.sha256, e.framework_version, e.target_id, e.mode, e.metrics_json
            FROM experiments e
            JOIN artifacts a ON a.path = e.source_path
            GROUP BY a.sha256, e.framework_version, e.target_id, e.mode, e.metrics_json
        )
        """
    ).fetchone()[0]
    observation_records = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    content_addressed_observations = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT a.sha256, o.source_line
            FROM observations o
            JOIN artifacts a ON a.path = o.source_path
            GROUP BY a.sha256, o.source_line
        )
        """
    ).fetchone()[0]
    logical_evidence_references = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT owner_type, owner_id, evidence_ref
            FROM evidence_links
            GROUP BY owner_type, owner_id, evidence_ref
        )
        """
    ).fetchone()[0]
    resolved_logical_evidence_references = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT owner_type, owner_id, evidence_ref, MAX(resolved) AS any_resolved
            FROM evidence_links
            GROUP BY owner_type, owner_id, evidence_ref
            HAVING any_resolved = 1
        )
        """
    ).fetchone()[0]
    return {
        "artifact_instances": artifact_instances,
        "unique_artifact_contents": unique_artifact_contents,
        "duplicate_artifact_instances": artifact_instances - unique_artifact_contents,
        "duplicate_artifact_groups": duplicate_artifact_groups,
        "experiment_records": experiment_records,
        "content_addressed_experiments": content_addressed_experiments,
        "observation_records": observation_records,
        "content_addressed_observations": content_addressed_observations,
        "evidence_link_instances": conn.execute("SELECT COUNT(*) FROM evidence_links").fetchone()[0],
        "logical_evidence_references": logical_evidence_references,
        "resolved_logical_evidence_references": resolved_logical_evidence_references,
        "unresolved_logical_evidence_references": logical_evidence_references - resolved_logical_evidence_references,
    }


def _logical_unresolved_evidence(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT owner_type, owner_id, evidence_ref, expected_sha256,
               MAX(resolved) AS any_resolved,
               MAX(CASE WHEN hash_match = 0 THEN 1 ELSE 0 END) AS has_hash_mismatch
        FROM evidence_links
        GROUP BY owner_type, owner_id, evidence_ref, expected_sha256
        HAVING any_resolved = 0
        ORDER BY owner_type, owner_id, evidence_ref
        """
    ).fetchall()
    source_status: dict[str, str | None] = {}
    for row in conn.execute("SELECT id, body_json FROM sources"):
        try:
            body = json.loads(row["body_json"] if isinstance(row, sqlite3.Row) else row[1])
        except (TypeError, json.JSONDecodeError):
            body = {}
        sid = row["id"] if isinstance(row, sqlite3.Row) else row[0]
        source_status[str(sid)] = body.get("ingestion_status")
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        expected_external = (
            item["owner_type"] == "source"
            and source_status.get(str(item["owner_id"])) == "artifact_expected_external"
        )
        item["expected_external"] = expected_external
        out.append(item)
    return out


def research_doctor(database: str | Path, *, duplicate_limit: int = 10) -> dict[str, Any]:
    """Audit evidence-base integrity without modifying the database.

    Archive duplication is reported separately from scientific evidence. Exact file
    copies remain indexed for provenance, while content-addressed counts prevent
    copied historical artifacts from being mistaken for independent runs.
    """
    db = Path(database)
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        inventory = _content_inventory(conn)
        unresolved = _logical_unresolved_evidence(conn)
        expected_external = [item for item in unresolved if item["expected_external"]]
        unexpected_unresolved = [item for item in unresolved if not item["expected_external"]]
        hash_mismatches = [
            dict(row) for row in conn.execute(
                """
                SELECT owner_type, owner_id, evidence_ref, expected_sha256, artifact_id
                FROM evidence_links
                WHERE hash_match = 0
                ORDER BY owner_type, owner_id, evidence_ref
                """
            )
        ]

        supported_claims_without_resolved = [
            row[0] for row in conn.execute(
                """
                SELECT c.id
                FROM claims c
                LEFT JOIN evidence_links e ON e.owner_type='claim' AND e.owner_id=c.id AND e.resolved=1
                WHERE c.status='supported'
                GROUP BY c.id
                HAVING COUNT(e.artifact_id)=0
                ORDER BY c.id
                """
            )
        ]
        findings_without_resolved = [
            row[0] for row in conn.execute(
                """
                SELECT f.id
                FROM findings f
                LEFT JOIN evidence_links e ON e.owner_type='finding' AND e.owner_id=f.id AND e.resolved=1
                GROUP BY f.id
                HAVING COUNT(e.artifact_id)=0
                ORDER BY f.id
                """
            )
        ]
        partially_unresolved_supported_claims = [
            row[0] for row in conn.execute(
                """
                SELECT c.id
                FROM claims c
                JOIN evidence_links e ON e.owner_type='claim' AND e.owner_id=c.id
                WHERE c.status='supported'
                GROUP BY c.id
                HAVING MAX(e.resolved)=1 AND MIN(e.resolved)=0
                ORDER BY c.id
                """
            )
        ]

        duplicate_groups: list[dict[str, Any]] = []
        for row in conn.execute(
            """
            SELECT sha256, COUNT(*) AS copies, MAX(size_bytes) AS size_bytes
            FROM artifacts
            GROUP BY sha256
            HAVING COUNT(*) > 1
            ORDER BY copies DESC, sha256
            LIMIT ?
            """,
            (max(0, duplicate_limit),),
        ):
            paths = [
                r[0] for r in conn.execute(
                    "SELECT path FROM artifacts WHERE sha256=? ORDER BY path LIMIT 5", (row["sha256"],)
                )
            ]
            duplicate_groups.append({**dict(row), "sample_paths": paths})

        version_coverage = [
            dict(row) for row in conn.execute(
                """
                WITH av AS (
                    SELECT version, COUNT(*) AS artifacts, COUNT(DISTINCT sha256) AS unique_artifact_contents
                    FROM artifacts WHERE version IS NOT NULL GROUP BY version
                ), ev AS (
                    SELECT framework_version AS version, COUNT(*) AS experiments
                    FROM experiments WHERE framework_version IS NOT NULL GROUP BY framework_version
                ), ov AS (
                    SELECT e.framework_version AS version, COUNT(o.id) AS observations
                    FROM experiments e JOIN observations o ON o.experiment_id=e.id
                    WHERE e.framework_version IS NOT NULL GROUP BY e.framework_version
                )
                SELECT av.version, av.artifacts, av.unique_artifact_contents,
                       COALESCE(ev.experiments,0) AS experiments, COALESCE(ov.observations,0) AS observations
                FROM av
                LEFT JOIN ev ON ev.version=av.version
                LEFT JOIN ov ON ov.version=av.version
                ORDER BY av.version
                """
            )
        ]

        integrity_failures = (
            len(unexpected_unresolved)
            + len(hash_mismatches)
            + len(supported_claims_without_resolved)
            + len(findings_without_resolved)
        )
        return {
            "schema": _SCHEMA_VERSION,
            "database": str(db),
            "content_inventory": inventory,
            "evidence_integrity": {
                "logical_references": inventory["logical_evidence_references"],
                "resolved_logical_references": inventory["resolved_logical_evidence_references"],
                "unresolved_logical_references": inventory["unresolved_logical_evidence_references"],
                "expected_external_unresolved": len(expected_external),
                "unexpected_unresolved": len(unexpected_unresolved),
                "hash_mismatches": len(hash_mismatches),
                "unresolved": unresolved,
                "hash_mismatch_details": hash_mismatches,
            },
            "knowledge_integrity": {
                "supported_claims_without_resolved_evidence": supported_claims_without_resolved,
                "findings_without_resolved_evidence": findings_without_resolved,
                "partially_unresolved_supported_claims": partially_unresolved_supported_claims,
            },
            "duplicate_content_groups": duplicate_groups,
            "version_coverage": version_coverage,
            "integrity_failures": integrity_failures,
            "ok": integrity_failures == 0,
        }


def research_summary(database: str | Path) -> dict[str, Any]:
    db = Path(database)
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        counts = {}
        for table in ("artifacts", "experiments", "observations", "claims", "findings", "decisions", "limitations", "sources", "hypotheses", "evidence_links"):
            counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        versions = [r[0] for r in conn.execute("SELECT DISTINCT framework_version FROM experiments WHERE framework_version IS NOT NULL ORDER BY framework_version")]
        artifact_versions = [r[0] for r in conn.execute("SELECT DISTINCT version FROM artifacts WHERE version IS NOT NULL ORDER BY version")]
        targets = [r[0] for r in conn.execute("SELECT DISTINCT target_id FROM experiments WHERE target_id IS NOT NULL ORDER BY target_id")]
        modes = [dict(r) for r in conn.execute("SELECT mode, COUNT(*) AS experiments FROM experiments GROUP BY mode ORDER BY mode")]
        claim_status = [dict(r) for r in conn.execute("SELECT COALESCE(status,'<none>') AS status, COUNT(*) AS count FROM claims GROUP BY status ORDER BY status")]
        hypothesis_status = [dict(r) for r in conn.execute("SELECT COALESCE(status,'<none>') AS status, COUNT(*) AS count FROM hypotheses GROUP BY status ORDER BY status")]
        resolved_links = conn.execute("SELECT COUNT(*) FROM evidence_links WHERE resolved=1").fetchone()[0]
        unresolved_links = conn.execute("SELECT COUNT(*) FROM evidence_links WHERE resolved=0").fetchone()[0]
        return {
            "schema": _SCHEMA_VERSION, "database": str(db), "counts": counts,
            "content_inventory": _content_inventory(conn),
            "framework_versions": versions, "artifact_versions": artifact_versions,
            "targets": targets, "modes": modes, "claim_status": claim_status, "hypothesis_status": hypothesis_status,
            "resolved_evidence_links": resolved_links, "unresolved_evidence_links": unresolved_links,
        }


def research_query(database: str | Path, term: str, *, limit: int = 20) -> list[dict[str, Any]]:
    db = Path(database)
    needle = f"%{term}%"
    results: list[dict[str, Any]] = []
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        for table, text_col in (("claims", "claim"), ("findings", "finding"), ("decisions", "decision"), ("limitations", "limitation"), ("terminology", "definition"), ("sources", "title"), ("hypotheses", "hypothesis")):
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE {text_col} LIKE ? OR body_json LIKE ? LIMIT ?",
                (needle, needle, limit),
            ).fetchall()
            for row in rows:
                item = dict(row)
                item["table"] = table
                results.append(item)
                if len(results) >= limit:
                    return results
        rows = conn.execute(
            "SELECT id,framework_version,target_id,mode,source_path,metrics_json FROM experiments WHERE metrics_json LIKE ? OR target_id LIKE ? OR mode LIKE ? LIMIT ?",
            (needle, needle, needle, max(0, limit - len(results))),
        ).fetchall()
        for row in rows:
            item = dict(row)
            item["table"] = "experiments"
            results.append(item)
    return results[:limit]
