"""Rapprochement firmware installé ↔ catalogue Dell, et calcul d'intégrité.

Le firmware remonté par l'iDRAC porte un nom (« BIOS », « iDRAC », « NIC
Broadcom … ») et une version. Le catalogue liste des paquets par identifiant de
composant / nom de périphérique. Le rapprochement exact (par PCI ID) est
complexe ; on procède ici par correspondance de nom et de type, en retenant, à
noms comparables, la **version officielle la plus récente**.

Statut d'intégrité :

* ``ok``      — la version installée == dernière version officielle : *intègre*.
* ``outdated``— une version officielle plus récente existe : *non conforme*,
                un bouton de mise à jour est proposé.
* ``unknown`` — aucun paquet correspondant trouvé dans le catalogue.

Rappel : le catalogue ne fournit pas de hash du firmware *installé*. Le
``hashMD5`` affiché est celui du paquet officiel (référence de téléchargement).
La conformité repose donc sur la comparaison de version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from catalog import CatalogComponent

STATUS_OK = "ok"
STATUS_OUTDATED = "outdated"
STATUS_UNKNOWN = "unknown"

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


def _tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {w for w in words if len(w) > 2 and w not in _STOPWORDS}


def _similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    inter = ta & tb
    union = ta | tb
    return len(inter) / len(union)


def _version_key(version: str) -> tuple:
    """Clé de tri d'une version, robuste aux formats Dell (``2.15.0``,
    ``A11``, ``21.85.22.30``…)."""
    parts = re.split(r"[.\-_]", version.strip())
    key: list[tuple[int, object]] = []
    for part in parts:
        m = re.match(r"^(\d+)$", part)
        if m:
            key.append((0, int(m.group(1))))
        else:
            key.append((1, part.lower()))
    return tuple(key)


@dataclass
class ComparisonRow:
    name: str
    component_type: str
    installed_version: str
    official_version: str
    reference_hash: str
    status: str
    download_url: str
    matched: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "component_type": self.component_type,
            "installed_version": self.installed_version,
            "official_version": self.official_version,
            "reference_hash": self.reference_hash,
            "status": self.status,
            "status_label": STATUS_LABELS[self.status],
            "download_url": self.download_url,
            "matched": self.matched,
        }


STATUS_LABELS = {
    STATUS_OK: "Intègre",
    STATUS_OUTDATED: "Non conforme",
    STATUS_UNKNOWN: "Inconnu",
}


class CatalogIndex:
    """Index du catalogue pour un rapprochement rapide par nom/type."""

    def __init__(self, components: list[CatalogComponent]) -> None:
        self.components = components

    def best_match(self, name: str, component_type: str = "") -> Optional[CatalogComponent]:
        best: Optional[CatalogComponent] = None
        best_score = 0.0
        for comp in self.components:
            score = _similarity(name, comp.name)
            if component_type and comp.component_type:
                if component_type.lower() == comp.component_type.lower():
                    score += 0.25
            if score > best_score:
                best_score = score
                best = comp
        # Seuil : en dessous, on considère qu'il n'y a pas de correspondance.
        return best if best_score >= 0.34 else None

    def latest_for(self, name: str, component_type: str = "") -> Optional[CatalogComponent]:
        """Version officielle la plus récente parmi les paquets comparables."""
        match = self.best_match(name, component_type)
        if match is None:
            return None
        # Regroupe tous les paquets « proches » du meilleur match et garde la
        # version la plus haute.
        candidates = [
            c
            for c in self.components
            if _similarity(match.name, c.name) >= 0.6
        ] or [match]
        return max(candidates, key=lambda c: _version_key(c.version))


def compare_inventory(
    installed: list,
    catalog: list[CatalogComponent],
) -> list[ComparisonRow]:
    """Produit une ligne de comparaison par firmware installé."""
    index = CatalogIndex(catalog)
    rows: list[ComparisonRow] = []
    for entry in installed:
        name = getattr(entry, "name", "") or ""
        comp_type = getattr(entry, "component_type", "") or ""
        installed_version = getattr(entry, "version", "") or ""
        official = index.latest_for(name, comp_type)
        rows.append(build_row(name, comp_type, installed_version, official))
    return rows


def build_row(
    name: str,
    component_type: str,
    installed_version: str,
    official: Optional[CatalogComponent],
) -> ComparisonRow:
    if official is None:
        return ComparisonRow(
            name=name,
            component_type=component_type,
            installed_version=installed_version,
            official_version="—",
            reference_hash="",
            status=STATUS_UNKNOWN,
            download_url="",
            matched=False,
        )

    status = _status_for(installed_version, official.version)
    return ComparisonRow(
        name=name,
        component_type=component_type or official.component_type,
        installed_version=installed_version,
        official_version=official.version,
        reference_hash=official.hash_md5,
        status=status,
        download_url=official.download_url if status == STATUS_OUTDATED else "",
        matched=True,
    )


def _status_for(installed_version: str, official_version: str) -> str:
    if not installed_version or not official_version:
        return STATUS_UNKNOWN
    if installed_version.strip().lower() == official_version.strip().lower():
        return STATUS_OK
    inst = _version_key(installed_version)
    off = _version_key(official_version)
    # Version installée >= officielle -> considérée conforme (à jour).
    if inst >= off:
        return STATUS_OK
    return STATUS_OUTDATED
