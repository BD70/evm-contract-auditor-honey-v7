"""Optional local-LLM judge that can downgrade probable false-positive findings.

Uses an OpenAI-compatible API (Ollama, vLLM, LM Studio, llama.cpp, LocalAI).
Requires the `openai` Python package (optional extra). Gracefully skips when
the package is absent or the server is unreachable — never blocks an audit.

Configuration via environment variables:
  EVM_LLM_BASE_URL   (default: http://localhost:11434/v1)
  EVM_LLM_MODEL      (default: qwen2.5-coder:14b)
  EVM_LLM_API_KEY    (default: local)
  EVM_LLM_TIMEOUT    (default: 30  — seconds per request)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# ── Verdict constants ──────────────────────────────────────────────────────────
VERDICT_VALID = "valid"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_NEEDS_HUMAN = "needs_human"
_VALID_VERDICTS = {VERDICT_VALID, VERDICT_FALSE_POSITIVE, VERDICT_NEEDS_HUMAN}

# ── Status labels mirrored from policy.py (imported lazily to avoid cycles) ───
_STATUS_PROBABLE = "probable_vulnerability"
_STATUS_SUSPICIOUS = "suspicious_behavior"
_WITNESS_SUPPRESSED = "suppressed_by_counter_evidence"
_WITNESS_INCONCLUSIVE = "analysis_inconclusive"

# ── Cache directory ────────────────────────────────────────────────────────────
_CACHE_DIR = Path("~/.cache/evm-auditor/llm-judge").expanduser()


@dataclass
class JudgeConfig:
    base_url: str = field(default_factory=lambda: os.environ.get("EVM_LLM_BASE_URL", "http://localhost:11434/v1"))
    model: str = field(default_factory=lambda: os.environ.get("EVM_LLM_MODEL", "qwen2.5-coder:14b"))
    api_key: str = field(default_factory=lambda: os.environ.get("EVM_LLM_API_KEY", "local"))
    timeout: float = field(default_factory=lambda: float(os.environ.get("EVM_LLM_TIMEOUT", "30")))
    refresh_cache: bool = False


@dataclass
class JudgeResult:
    verdict: str  # valid | false_positive | needs_human
    rationale: str
    confidence: float
    cached: bool = False
    judged_at: float = field(default_factory=time.time)


# ── Availability check ─────────────────────────────────────────────────────────

def is_available(cfg: JudgeConfig) -> bool:
    """Return True if the openai package is installed and the base URL is reachable."""
    try:
        import openai  # noqa: F401
    except ImportError:
        return False
    try:
        import urllib.request
        models_url = cfg.base_url.rstrip("/") + "/models"
        req = urllib.request.Request(models_url, headers={"Authorization": f"Bearer {cfg.api_key}"})
        with urllib.request.urlopen(req, timeout=3):
            pass
        return True
    except Exception:
        return False


# ── Cache helpers ──────────────────────────────────────────────────────────────

def cache_key(bytecode_identity: str, rule_id: str, binding_summary: str) -> str:
    raw = f"{bytecode_identity}|{rule_id}|{binding_summary}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_path(key: str) -> Path:
    return _CACHE_DIR / f"{key}.json"


def _read_cache(key: str) -> JudgeResult | None:
    p = _cache_path(key)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        return JudgeResult(
            verdict=data["verdict"],
            rationale=data.get("rationale", ""),
            confidence=float(data.get("confidence", 0.5)),
            cached=True,
            judged_at=float(data.get("judged_at", 0)),
        )
    except Exception:
        return None


def _write_cache(key: str, result: JudgeResult) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _cache_path(key).write_text(json.dumps({
        "verdict": result.verdict,
        "rationale": result.rationale,
        "confidence": result.confidence,
        "judged_at": result.judged_at,
    }))


# ── Prompt construction ────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a senior smart-contract security auditor reviewing a potential vulnerability finding \
produced by a static bytecode analyzer. Your job is to assess whether the finding is a real \
vulnerability or a false positive.

Respond ONLY with a JSON object — no prose, no markdown, no code fences. The object must \
have exactly these three fields:
  "verdict":    one of "valid", "false_positive", or "needs_human"
  "rationale":  one sentence explaining your verdict
  "confidence": a float between 0.0 and 1.0

"valid"          — the finding appears to be a genuine vulnerability worth reporting.
"false_positive" — the finding is clearly not exploitable given the context.
"needs_human"    — you cannot determine without additional context.
"""


def _build_prompt(finding: dict[str, Any], audit_slice: dict[str, Any]) -> str:
    rule_id = finding.get("rule_id", "unknown")
    intent = audit_slice.get("intent", {})
    witness_goal = finding.get("witness_goal") or {}
    tech_summary = finding.get("technical_summary", "")
    exploit_narrative = finding.get("exploit_narrative", "")
    pseudocode = audit_slice.get("pseudocode", "")
    slot_slice = audit_slice.get("slot_slice", {})

    lines = [
        f"Rule: {rule_id}",
        f"Vulnerability class: {intent.get('vulnerability_class', 'unknown')}",
        f"Attack thesis: {intent.get('attack_thesis', '')}",
        "",
        f"Technical summary: {tech_summary}",
        f"Exploit narrative: {exploit_narrative}",
    ]
    if witness_goal.get("success_condition"):
        lines.append(f"Success condition: {witness_goal['success_condition']}")
    if pseudocode:
        lines.append(f"\nRelevant pseudocode:\n{pseudocode[:2000]}")
    if slot_slice:
        lines.append(f"\nStorage context (JSON):\n{json.dumps(slot_slice, indent=2)[:1000]}")
    return "\n".join(lines)


def _build_audit_slice(finding: dict[str, Any], audit: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    """Build a compact, privacy-safe slice of audit context for the prompt."""
    state_model = audit.get("state_model", {})
    relevant_slots = []
    for slot in state_model.get("slot_index", []):
        if slot.get("semantic_role") in ("balance", "owner", "price", "reserve", "totalSupply", "share_price"):
            relevant_slots.append({
                "slot": slot.get("slot"),
                "role": slot.get("semantic_role"),
                "role_confidence": slot.get("role_confidence"),
            })

    fn_selector = (finding.get("function") or {}).get("selector")
    pseudocode = ""
    for fn in audit.get("functions", []):
        if fn.get("selector") == fn_selector and fn.get("pseudocode"):
            pseudocode = fn["pseudocode"]
            break

    return {
        "intent": rule.get("intent", {}),
        "pseudocode": pseudocode,
        "slot_slice": {"relevant_slots": relevant_slots[:5]},
    }


# ── Judge invocation ───────────────────────────────────────────────────────────

def judge_finding(
    finding: dict[str, Any],
    audit: dict[str, Any],
    rule: dict[str, Any],
    cfg: JudgeConfig,
) -> JudgeResult | None:
    """Invoke the LLM judge on a single finding. Returns None on any error."""
    try:
        import openai
    except ImportError:
        _log.debug("openai package not installed; skipping LLM judge")
        return None

    bytecode_id = audit.get("bytecode_identity", {}).get("keccak256", "unknown")
    rule_id = finding.get("rule_id", "unknown")
    binding_summary = json.dumps(finding.get("evidence", {}).get("details", {}).get("bindings", {}), sort_keys=True)
    key = cache_key(bytecode_id, rule_id, binding_summary)

    if not cfg.refresh_cache:
        cached = _read_cache(key)
        if cached is not None:
            return cached

    audit_slice = _build_audit_slice(finding, audit, rule)
    prompt = _build_prompt(finding, audit_slice)

    try:
        client = openai.OpenAI(base_url=cfg.base_url, api_key=cfg.api_key)
        kwargs: dict[str, Any] = {
            "model": cfg.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "timeout": cfg.timeout,
            "max_tokens": 256,
            "temperature": 0.1,
        }
        try:
            kwargs["response_format"] = {"type": "json_object"}
            response = client.chat.completions.create(**kwargs)
        except Exception:
            kwargs.pop("response_format", None)
            response = client.chat.completions.create(**kwargs)

        raw = response.choices[0].message.content or ""
        result = _parse_verdict(raw, key)
        if result is not None:
            _write_cache(key, result)
        return result

    except Exception as exc:
        _log.warning("LLM judge request failed for %s: %s", rule_id, exc)
        return None


def _parse_verdict(raw: str, cache_key_hint: str) -> JudgeResult | None:
    """Parse JSON verdict from model output; retry with explicit instruction on failure."""
    raw = raw.strip()
    # Strip markdown fences if present
    if raw.startswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(line for line in lines if not line.startswith("```"))
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        _log.debug("LLM judge returned non-JSON for key %s: %r", cache_key_hint, raw[:200])
        return None

    verdict = str(data.get("verdict", "")).strip()
    if verdict not in _VALID_VERDICTS:
        return JudgeResult(verdict=VERDICT_NEEDS_HUMAN, rationale="model returned unexpected verdict", confidence=0.5)

    return JudgeResult(
        verdict=verdict,
        rationale=str(data.get("rationale", ""))[:500],
        confidence=min(1.0, max(0.0, float(data.get("confidence", 0.5)))),
    )


# ── Status downgrade logic ─────────────────────────────────────────────────────

def apply_judge_result(finding: dict[str, Any], result: JudgeResult) -> dict[str, Any]:
    """Downgrade finding status based on judge verdict. Never upgrades."""
    finding = dict(finding)
    finding["judged_by"] = "llm"
    finding["judge_verdict"] = result.verdict
    finding["judge_rationale"] = result.rationale
    finding["judge_confidence"] = result.confidence

    status = finding.get("status", "")
    if result.verdict == VERDICT_FALSE_POSITIVE:
        if status == _STATUS_PROBABLE:
            finding["status"] = _WITNESS_INCONCLUSIVE
            finding["witness_status"] = _WITNESS_INCONCLUSIVE
        elif status == _STATUS_SUSPICIOUS:
            finding["status"] = _WITNESS_SUPPRESSED
            finding["witness_status"] = _WITNESS_SUPPRESSED
    elif result.verdict == VERDICT_NEEDS_HUMAN:
        finding["requires_manual_review"] = True

    return finding


def run_judge_pass(
    findings: list[dict[str, Any]],
    audit: dict[str, Any],
    rules_by_id: dict[str, dict[str, Any]],
    cfg: JudgeConfig,
) -> list[dict[str, Any]]:
    """Run the LLM judge over a list of findings, skipping suppressed ones."""
    out = []
    for finding in findings:
        status = finding.get("status", "")
        # Never send suppressed findings to the model
        if status in (_WITNESS_SUPPRESSED, _WITNESS_INCONCLUSIVE):
            out.append(finding)
            continue
        rule_id = finding.get("rule_id", "")
        rule = rules_by_id.get(rule_id, {})
        result = judge_finding(finding, audit, rule, cfg)
        if result is not None:
            finding = apply_judge_result(finding, result)
        out.append(finding)
    return out
