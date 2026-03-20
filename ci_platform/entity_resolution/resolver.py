import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class IdentifierType(Enum):
    EMAIL = "email"
    UPN = "upn"
    SAM = "sam"
    SID = "sid"
    DISPLAY_NAME = "display_name"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    HASH = "hash"


# Types that belong to an asset rather than a user
_ASSET_TYPES = {IdentifierType.HOSTNAME, IdentifierType.IP_ADDRESS}

# Display-name priority (lower index = higher priority)
_DISPLAY_PRIORITY = [
    IdentifierType.DISPLAY_NAME,
    IdentifierType.EMAIL,
    IdentifierType.UPN,
    IdentifierType.SAM,
    IdentifierType.SID,
    IdentifierType.HASH,
]


@dataclass
class Identifier:
    value: str
    id_type: IdentifierType
    source: str
    confidence: float = 1.0


@dataclass
class ResolvedEntity:
    canonical_id: str
    entity_type: str
    identifiers: List[Identifier]
    display_name: str
    merge_count: int
    resolution_method: str


class EntityResolver:
    def __init__(self, domain_rules: Optional[Dict] = None):
        self._domain_rules = domain_rules or {}

    # ── public API ───────────────────────────────────────────────────────────

    def resolve(self, identifiers: List[Identifier]) -> List[ResolvedEntity]:
        if not identifiers:
            return []

        groups = self._build_merge_groups(identifiers)

        entities = []
        for group in groups:
            members = [identifiers[i] for i in group]
            entity_type = self._infer_entity_type(members)
            method = self._resolution_method(members)
            entities.append(ResolvedEntity(
                canonical_id=self._canonical_id(members),
                entity_type=entity_type,
                identifiers=members,
                display_name=self._best_display_name(members),
                merge_count=len(members),
                resolution_method=method,
            ))
        return entities

    def compute_completeness(self, entities: List[ResolvedEntity]) -> float:
        """Fraction of entities with >= 2 distinct identifier types."""
        if not entities:
            return 0.0
        rich = sum(
            1 for e in entities
            if len({i.id_type for i in e.identifiers}) >= 2
        )
        return rich / len(entities)

    # ── normalization ────────────────────────────────────────────────────────

    def _normalize(self, value: str, id_type: IdentifierType) -> str:
        value = value.strip()
        if id_type in (IdentifierType.EMAIL, IdentifierType.UPN):
            return value.lower()
        if id_type == IdentifierType.SAM:
            # FIRM\jsmith → jsmith
            if "\\" in value:
                return value.split("\\", 1)[1].lower()
            return value.lower()
        if id_type == IdentifierType.SID:
            return value  # case-sensitive
        if id_type == IdentifierType.HOSTNAME:
            return value.upper()
        if id_type == IdentifierType.DISPLAY_NAME:
            return value.lower()
        return value.lower()

    def _extract_local_part(self, value: str, id_type: IdentifierType) -> str:
        if id_type in (IdentifierType.EMAIL, IdentifierType.UPN):
            return value.split("@")[0].lower()
        if id_type == IdentifierType.SAM:
            if "\\" in value:
                return value.split("\\", 1)[1].lower()
            return value.lower()
        if id_type == IdentifierType.DISPLAY_NAME:
            # "John Smith" → "john.smith" tokens for fuzzy matching
            return ".".join(value.lower().split())
        return value.lower()

    # ── grouping ─────────────────────────────────────────────────────────────

    def _build_merge_groups(self, identifiers: List[Identifier]) -> List[Set[int]]:
        n = len(identifiers)
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            parent[find(a)] = find(b)

        # Pass 1 — exact match (normalized value + same broad category)
        norm_map: Dict[tuple, List[int]] = {}
        for i, ident in enumerate(identifiers):
            key = (self._normalize(ident.value, ident.id_type), ident.id_type)
            norm_map.setdefault(key, []).append(i)
        for indices in norm_map.values():
            for j in range(1, len(indices)):
                union(indices[0], indices[j])

        # Pass 2 — domain rules: cross-type linking via local-part equality
        local_parts: Dict[str, List[int]] = {}
        linkable = {IdentifierType.EMAIL, IdentifierType.UPN, IdentifierType.SAM}
        for i, ident in enumerate(identifiers):
            if ident.id_type in linkable:
                lp = self._extract_local_part(ident.value, ident.id_type)
                if lp:
                    local_parts.setdefault(lp, []).append(i)
        for indices in local_parts.values():
            for j in range(1, len(indices)):
                union(indices[0], indices[j])

        # Pass 2b — display name matching: display_name tokens ⊇ email_local tokens
        dn_entries: List[tuple] = []  # (index, set_of_tokens)
        for i, ident in enumerate(identifiers):
            if ident.id_type == IdentifierType.DISPLAY_NAME:
                tokens = set(re.split(r"[\s.\-_]+", self._normalize(ident.value, ident.id_type)))
                tokens.discard("")
                dn_entries.append((i, tokens))

        for i, ident in enumerate(identifiers):
            if ident.id_type in (IdentifierType.EMAIL, IdentifierType.UPN, IdentifierType.SAM):
                lp = self._extract_local_part(ident.value, ident.id_type)
                lp_tokens = set(re.split(r"[\s.\-_]+", lp))
                lp_tokens.discard("")
                if not lp_tokens:
                    continue
                for j, dn_tokens in dn_entries:
                    if lp_tokens <= dn_tokens:
                        union(i, j)

        # Pass 3 — hash linking: identical HASH values → same entity
        hash_map: Dict[str, List[int]] = {}
        for i, ident in enumerate(identifiers):
            if ident.id_type == IdentifierType.HASH:
                hash_map.setdefault(ident.value, []).append(i)
        for indices in hash_map.values():
            for j in range(1, len(indices)):
                union(indices[0], indices[j])

        # Collect groups
        groups: Dict[int, Set[int]] = {}
        for i in range(n):
            root = find(i)
            groups.setdefault(root, set()).add(i)
        return list(groups.values())

    # ── helpers ──────────────────────────────────────────────────────────────

    def _canonical_id(self, identifiers: List[Identifier]) -> str:
        norm_values = sorted(
            self._normalize(ident.value, ident.id_type)
            for ident in identifiers
        )
        payload = "|".join(norm_values)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def _best_display_name(self, identifiers: List[Identifier]) -> str:
        by_type: Dict[IdentifierType, str] = {
            ident.id_type: ident.value for ident in identifiers
        }
        for id_type in _DISPLAY_PRIORITY:
            if id_type in by_type:
                return by_type[id_type]
        return identifiers[0].value

    def _infer_entity_type(self, identifiers: List[Identifier]) -> str:
        types = {ident.id_type for ident in identifiers}
        if types & _ASSET_TYPES and not (
            types & {IdentifierType.EMAIL, IdentifierType.UPN,
                     IdentifierType.SAM, IdentifierType.DISPLAY_NAME}
        ):
            return "asset"
        return "user"

    def _resolution_method(self, identifiers: List[Identifier]) -> str:
        if len(identifiers) == 1:
            return "exact"
        types = {ident.id_type for ident in identifiers}
        if len(types) == 1:
            return "exact"
        if IdentifierType.HASH in types and types <= {IdentifierType.HASH}:
            return "exact"
        if types & {IdentifierType.EMAIL, IdentifierType.UPN, IdentifierType.SAM}:
            return "domain_match"
        return "exact"
