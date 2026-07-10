"""Helpers de correspondance de noms et de comparaison de versions.

Regroupés ici pour être partagés par ``compare.py`` (rapprochement catalogue)
et ``baseline.py`` (rapprochement empreintes de référence) sans import
circulaire.
"""

from __future__ import annotations

import re

_STOPWORDS = {
    "firmware",
    "controller",
    "adapter",
    "card",
    "for",
    "dell",
    "the",
    "and",
    "network",
    "device",
    "system",
}


def tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {w for w in words if len(w) > 2 and w not in _STOPWORDS}


def similarity(a: str, b: str) -> float:
    """Similarité de Jaccard sur les jetons de deux libellés (0..1)."""
    ta, tb = tokens(a), tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def version_key(version: str) -> tuple:
    """Clé de tri robuste aux formats Dell (``2.16.0``, ``A11``,
    ``21.85.22.30``, ``52.26.0-5179``…)."""
    parts = re.split(r"[.\-_]", (version or "").strip())
    key: list[tuple[int, object]] = []
    for part in parts:
        if re.fullmatch(r"\d+", part):
            key.append((0, int(part)))
        else:
            key.append((1, part.lower()))
    return tuple(key)


def versions_equal(a: str, b: str) -> bool:
    return (a or "").strip().lower() == (b or "").strip().lower()


def version_ge(a: str, b: str) -> bool:
    """Vrai si la version ``a`` est supérieure ou égale à ``b``."""
    return version_key(a) >= version_key(b)


def normalize_hash(value: str) -> str:
    return (value or "").strip().lower().replace("0x", "")
