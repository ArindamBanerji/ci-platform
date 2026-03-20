import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class RedactionStrategy(Enum):
    HASH = "hash"
    MASK = "mask"
    REMOVE = "remove"


@dataclass
class RedactionResult:
    original_type: str
    strategy: RedactionStrategy
    redacted_value: str
    position: Tuple[int, int]


@dataclass
class RedactionReport:
    total_redactions: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    results: List[RedactionResult] = field(default_factory=list)


class PIIRedactor:
    PATTERNS: Dict[str, Tuple[str, RedactionStrategy]] = {
        "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", RedactionStrategy.HASH),
        "credit_card": (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", RedactionStrategy.MASK),
        "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", RedactionStrategy.HASH),
        "phone": (r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", RedactionStrategy.MASK),
        "ip_address": (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", RedactionStrategy.HASH),
    }

    EXEMPT_FIELDS = {
        "alert_type", "category", "severity",
        "timestamp", "source", "alert_id", "decision_id",
    }

    def __init__(
        self,
        strategy_overrides: Optional[Dict[str, RedactionStrategy]] = None,
        custom_patterns: Optional[Dict[str, str]] = None,
        hash_salt: str = "soccopilot_pii_salt",
    ):
        self._strategy_overrides = strategy_overrides or {}
        self._custom_patterns = custom_patterns or {}
        self._hash_salt = hash_salt

    def redact_text(self, text: str) -> Tuple[str, RedactionReport]:
        report = RedactionReport()
        matches: List[Tuple[int, int, str, RedactionStrategy]] = []

        # Phase 1: built-in regex patterns
        for pii_type, (pattern, default_strategy) in self.PATTERNS.items():
            strategy = self._strategy_overrides.get(pii_type, default_strategy)
            for m in re.finditer(pattern, text):
                matches.append((m.start(), m.end(), pii_type, strategy))

        # Phase 3: custom patterns (default strategy MASK)
        for pii_type, pattern in self._custom_patterns.items():
            strategy = self._strategy_overrides.get(pii_type, RedactionStrategy.MASK)
            for m in re.finditer(pattern, text):
                matches.append((m.start(), m.end(), pii_type, strategy))

        # Phase 2: optional spaCy NER
        ner_results = self._run_ner(text)
        for r in ner_results:
            matches.append((r.position[0], r.position[1], r.original_type, r.strategy))

        # Deduplicate overlapping matches (keep longest)
        matches = _deduplicate(matches)

        # Apply in reverse order so positions stay valid
        matches.sort(key=lambda x: x[0], reverse=True)
        result_text = text
        for start, end, pii_type, strategy in matches:
            original = result_text[start:end]
            replacement = self._apply_strategy(original, pii_type, strategy)
            result_text = result_text[:start] + replacement + result_text[end:]
            rr = RedactionResult(
                original_type=pii_type,
                strategy=strategy,
                redacted_value=replacement,
                position=(start, end),
            )
            report.results.append(rr)
            report.by_type[pii_type] = report.by_type.get(pii_type, 0) + 1
            report.total_redactions += 1

        return result_text, report

    def redact_dict(self, data: Any, _exempt: bool = False) -> Tuple[Any, RedactionReport]:
        combined = RedactionReport()

        if isinstance(data, dict):
            clean: Dict[str, Any] = {}
            for key, value in data.items():
                exempt = key in self.EXEMPT_FIELDS
                clean_val, sub_report = self.redact_dict(value, _exempt=exempt)
                clean[key] = clean_val
                _merge_reports(combined, sub_report)
            return clean, combined

        if isinstance(data, list):
            clean_list = []
            for item in data:
                clean_item, sub_report = self.redact_dict(item, _exempt=_exempt)
                clean_list.append(clean_item)
                _merge_reports(combined, sub_report)
            return clean_list, combined

        if isinstance(data, str) and not _exempt:
            clean_str, sub_report = self.redact_text(data)
            _merge_reports(combined, sub_report)
            return clean_str, combined

        return data, combined

    def _apply_strategy(self, value: str, pii_type: str, strategy: RedactionStrategy) -> str:
        if strategy == RedactionStrategy.HASH:
            return self._hash_value(value)
        if strategy == RedactionStrategy.MASK:
            return f"[REDACTED-{pii_type.upper()}]"
        # REMOVE
        return ""

    def _hash_value(self, value: str) -> str:
        payload = self._hash_salt + value
        digest = hashlib.sha256(payload.encode()).hexdigest()
        return digest[:12]

    def _run_ner(self, text: str) -> List[RedactionResult]:
        try:
            import spacy  # noqa: F401
        except ImportError:
            return []

        try:
            nlp = _get_spacy_model()
            doc = nlp(text)
        except Exception:
            return []

        results = []
        for ent in doc.ents:
            if ent.label_ in ("PERSON", "ORG", "GPE", "LOC"):
                pii_type = f"ner_{ent.label_.lower()}"
                strategy = self._strategy_overrides.get(pii_type, RedactionStrategy.MASK)
                results.append(RedactionResult(
                    original_type=pii_type,
                    strategy=strategy,
                    redacted_value=self._apply_strategy(ent.text, pii_type, strategy),
                    position=(ent.start_char, ent.end_char),
                ))
        return results


# ── helpers ──────────────────────────────────────────────────────────────────

def _deduplicate(
    matches: List[Tuple[int, int, str, RedactionStrategy]]
) -> List[Tuple[int, int, str, RedactionStrategy]]:
    """Remove overlapping spans, keeping the longest match."""
    if not matches:
        return matches
    matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    kept = [matches[0]]
    for m in matches[1:]:
        prev = kept[-1]
        if m[0] < prev[1]:  # overlaps
            if (m[1] - m[0]) > (prev[1] - prev[0]):
                kept[-1] = m
        else:
            kept.append(m)
    return kept


def _merge_reports(target: RedactionReport, source: RedactionReport) -> None:
    target.total_redactions += source.total_redactions
    for k, v in source.by_type.items():
        target.by_type[k] = target.by_type.get(k, 0) + v
    target.results.extend(source.results)


_spacy_model_cache = None


def _get_spacy_model():
    global _spacy_model_cache
    if _spacy_model_cache is None:
        import spacy
        _spacy_model_cache = spacy.load("en_core_web_sm")
    return _spacy_model_cache
