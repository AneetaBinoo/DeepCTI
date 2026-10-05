"""Provenance-tracked Belnap–Dunn evidence state (plan §3.1–§3.3).

An observation is ``(atom, polarity, source, t, h)``. Sources carry a trust class and an
independence group. The value of an atom is computed from the *latest* fresh observation of
each trusted source; support is counted in independence groups, not in sources.
Untrusted observations never change the value; they are kept as hints.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum


class Belnap(str, Enum):
    N = "N"  # no information
    T = "T"  # told true only
    F = "F"  # told false only
    B = "B"  # told both

    @classmethod
    def from_support(cls, positive: int, negative: int) -> Belnap:
        if positive and negative:
            return cls.B
        if positive:
            return cls.T
        if negative:
            return cls.F
        return cls.N


def leq_k(a: Belnap, b: Belnap) -> bool:
    """Information order: N <=k T, F <=k B."""
    if a == b or a == Belnap.N or b == Belnap.B:
        return True
    return False


TRUSTED = "T"
UNTRUSTED = "U"


@dataclass(frozen=True)
class Source:
    name: str
    trust: str  # "T" or "U"
    group: str

    def __post_init__(self) -> None:
        if self.trust not in (TRUSTED, UNTRUSTED):
            raise ValueError(f"trust must be T or U, got {self.trust!r}")


@dataclass(frozen=True)
class Observation:
    atom: str
    positive: bool
    source: Source
    t: float
    h: str  # content hash of the raw tool output the observation was derived from
    evidence_id: str = ""
    detail: str = ""

    def key(self) -> tuple:
        return (self.atom, self.positive, self.source.name, self.t, self.h)


def content_hash(payload: object) -> str:
    raw = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class EvidenceLog:
    """Append-only log. Only tool executions and mirror reads write here (invariant A1)."""

    _items: list[Observation] = field(default_factory=list)
    _keys: set[tuple] = field(default_factory=set)

    def append(self, obs: Observation) -> bool:
        key = obs.key()
        if key in self._keys:  # idempotent duplicate ingestion
            return False
        self._keys.add(key)
        self._items.append(obs)
        return True

    def extend(self, items: Iterable[Observation]) -> int:
        return sum(self.append(item) for item in items)

    def __iter__(self):
        return iter(list(self._items))

    def __len__(self) -> int:
        return len(self._items)


@dataclass(frozen=True)
class AtomState:
    atom: str
    val: Belnap
    pos_groups: frozenset[str]
    neg_groups: frozenset[str]
    hints_pos: int = 0
    hints_neg: int = 0
    stale_dropped: int = 0
    evidence_ids: tuple[str, ...] = ()

    @property
    def kappa_pos(self) -> int:
        return len(self.pos_groups)

    @property
    def kappa_neg(self) -> int:
        return len(self.neg_groups)

    def to_dict(self) -> dict:
        return {
            "val": self.val.value,
            "kappa_pos": self.kappa_pos,
            "kappa_neg": self.kappa_neg,
            "pos_groups": sorted(self.pos_groups),
            "neg_groups": sorted(self.neg_groups),
            "hints_pos": self.hints_pos,
            "hints_neg": self.hints_neg,
            "stale_dropped": self.stale_dropped,
            "evidence_ids": list(self.evidence_ids),
        }


def _latest_per_source(observations: Iterable[Observation]) -> dict[tuple[str, str], Observation]:
    latest: dict[tuple[str, str], Observation] = {}
    for obs in observations:
        key = (obs.atom, obs.source.name)
        cur = latest.get(key)
        # latest by collection time; ties broken by content hash then polarity (total order)
        if cur is None or (obs.t, obs.h, obs.positive) > (cur.t, cur.h, cur.positive):
            latest[key] = obs
    return latest


def compute_state(
    log: Iterable[Observation],
    t_now: float,
    freshness: Mapping[str, float] | None = None,
    default_freshness: float = math.inf,
) -> dict[str, AtomState]:
    """Belnap state for every atom mentioned in ``log`` (plan §3.3)."""
    freshness = freshness or {}
    latest = _latest_per_source(log)
    pos: dict[str, set[str]] = {}
    neg: dict[str, set[str]] = {}
    hints: dict[str, list[int]] = {}
    stale: dict[str, int] = {}
    ev: dict[str, set[str]] = {}
    atoms: set[str] = set()
    for (atom, _), obs in latest.items():
        atoms.add(atom)
        if obs.source.trust != TRUSTED:
            h = hints.setdefault(atom, [0, 0])
            h[0 if obs.positive else 1] += 1
            continue
        window = freshness.get(atom, default_freshness)
        if t_now - obs.t > window:
            stale[atom] = stale.get(atom, 0) + 1
            continue
        (pos if obs.positive else neg).setdefault(atom, set()).add(obs.source.group)
        if obs.evidence_id:
            ev.setdefault(atom, set()).add(obs.evidence_id)
    out = {}
    for atom in atoms:
        p = frozenset(pos.get(atom, ()))
        n = frozenset(neg.get(atom, ()))
        hp, hn = hints.get(atom, [0, 0])
        out[atom] = AtomState(
            atom=atom,
            val=Belnap.from_support(len(p), len(n)),
            pos_groups=p,
            neg_groups=n,
            hints_pos=hp,
            hints_neg=hn,
            stale_dropped=stale.get(atom, 0),
            evidence_ids=tuple(sorted(ev.get(atom, ()))),
        )
    return out


def val(state: Mapping[str, AtomState], atom: str) -> Belnap:
    item = state.get(atom)
    return item.val if item else Belnap.N


def kappa_pos(state: Mapping[str, AtomState], atom: str) -> int:
    item = state.get(atom)
    return item.kappa_pos if item else 0
