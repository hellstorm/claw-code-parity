"""Rapprochement firmware installé ↔ catalogue Dell + baseline, sur **deux
axes distincts et indépendants** :

1. **Intégrité (hash)** — l'axe de sécurité, primordial. À *version égale*,
   on compare le hash mesuré du firmware installé à l'empreinte de référence
   connue-bonne (baseline) :

   * ``ok``           — hash identique : *intègre*.
   * ``compromised``  — même version, hash différent : **compromis** (alerte).
   * ``unverifiable`` — pas de hash mesuré et/ou pas de référence : *non
                        vérifiable*.

2. **Mise à jour (version)** — informatif. On compare la version installée à
   la dernière version officielle du catalogue :

   * ``current``   — à jour.
   * ``available`` — une version plus récente existe (bouton de mise à jour).
   * ``unknown``   — aucun paquet correspondant au catalogue.

Les deux états sont calculés séparément : un firmware peut être **intègre mais
à mettre à jour**, ou **à jour mais compromis** (cas le plus grave). L'axe
intégrité prime sur l'axe mise à jour dans la hiérarchie de sécurité.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from baseline import Baseline, BaselineEntry
from catalog import CatalogComponent
from matching import normalize_hash, similarity, version_ge, versions_equal

# --- Axe intégrité (sécurité) ------------------------------------------------
INTEGRITY_OK = "ok"
INTEGRITY_COMPROMISED = "compromised"
INTEGRITY_UNVERIFIABLE = "unverifiable"

INTEGRITY_LABELS = {
    INTEGRITY_OK: "Intègre",
    INTEGRITY_COMPROMISED: "Compromis",
    INTEGRITY_UNVERIFIABLE: "Non vérifiable",
}

# --- Axe mise à jour (version) ----------------------------------------------
UPDATE_CURRENT = "current"
UPDATE_AVAILABLE = "available"
UPDATE_UNKNOWN = "unknown"

UPDATE_LABELS = {
    UPDATE_CURRENT: "À jour",
    UPDATE_AVAILABLE: "Mise à jour disponible",
    UPDATE_UNKNOWN: "Inconnu",
}


@dataclass
class ComparisonRow:
    name: str
    component_type: str
    installed_version: str
    official_version: str
    # Axe intégrité
    integrity: str
    measured_hash: str
    expected_hash: str
    hash_algorithm: str
    # Axe mise à jour
    update: str
    package_hash: str
    download_url: str
    matched: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "component_type": self.component_type,
            "installed_version": self.installed_version,
            "official_version": self.official_version,
            "integrity": self.integrity,
            "integrity_label": INTEGRITY_LABELS[self.integrity],
            "measured_hash": self.measured_hash,
            "expected_hash": self.expected_hash,
            "hash_algorithm": self.hash_algorithm,
            "update": self.update,
            "update_label": UPDATE_LABELS[self.update],
            "package_hash": self.package_hash,
            "download_url": self.download_url,
            "matched": self.matched,
        }


class CatalogIndex:
    """Index du catalogue pour un rapprochement rapide par nom/type."""

    def __init__(self, components: list[CatalogComponent]) -> None:
        self.components = components

    def best_match(self, name: str, component_type: str = "") -> Optional[CatalogComponent]:
        best: Optional[CatalogComponent] = None
        best_score = 0.0
        for comp in self.components:
            score = similarity(name, comp.name)
            if component_type and comp.component_type:
                if component_type.lower() == comp.component_type.lower():
                    score += 0.25
            if score > best_score:
                best_score = score
                best = comp
        return best if best_score >= 0.34 else None

    def latest_for(self, name: str, component_type: str = "") -> Optional[CatalogComponent]:
        match = self.best_match(name, component_type)
        if match is None:
            return None
        candidates = [c for c in self.components if similarity(match.name, c.name) >= 0.6] or [match]
        from matching import version_key

        return max(candidates, key=lambda c: version_key(c.version))


def compute_integrity(measured_hash: str, reference: Optional[BaselineEntry]) -> str:
    """Statut d'intégrité. ``reference`` est déjà apparié à version égale."""
    if not measured_hash or reference is None or not reference.hash:
        return INTEGRITY_UNVERIFIABLE
    if normalize_hash(measured_hash) == reference.normalized_hash:
        return INTEGRITY_OK
    return INTEGRITY_COMPROMISED


def compute_update(installed_version: str, official: Optional[CatalogComponent]) -> str:
    """Statut de mise à jour (axe version)."""
    if official is None or not official.version or not installed_version:
        return UPDATE_UNKNOWN
    if versions_equal(installed_version, official.version) or version_ge(
        installed_version, official.version
    ):
        return UPDATE_CURRENT
    return UPDATE_AVAILABLE


def build_row(
    name: str,
    component_type: str,
    installed_version: str,
    measured_hash: str,
    hash_algorithm: str,
    official: Optional[CatalogComponent],
    reference: Optional[BaselineEntry],
) -> ComparisonRow:
    integrity = compute_integrity(measured_hash, reference)
    update = compute_update(installed_version, official)
    return ComparisonRow(
        name=name,
        component_type=component_type or (official.component_type if official else ""),
        installed_version=installed_version,
        official_version=official.version if official else "—",
        integrity=integrity,
        measured_hash=measured_hash,
        expected_hash=reference.hash if reference else "",
        hash_algorithm=hash_algorithm or (reference.algorithm if reference else ""),
        update=update,
        package_hash=official.hash_md5 if official else "",
        download_url=official.download_url if update == UPDATE_AVAILABLE else "",
        matched=official is not None,
    )


def compare_inventory(
    installed: list,
    catalog: list[CatalogComponent],
    baseline: Optional[Baseline] = None,
) -> list[ComparisonRow]:
    """Produit une ligne de comparaison (2 axes) par firmware installé."""
    index = CatalogIndex(catalog)
    base = baseline or Baseline([])
    rows: list[ComparisonRow] = []
    for entry in installed:
        name = getattr(entry, "name", "") or ""
        comp_type = getattr(entry, "component_type", "") or ""
        installed_version = getattr(entry, "version", "") or ""
        measured_hash = getattr(entry, "measured_hash", "") or ""
        hash_algorithm = getattr(entry, "hash_algorithm", "") or ""
        official = index.latest_for(name, comp_type)
        reference = base.reference_for(name, installed_version)
        rows.append(
            build_row(
                name,
                comp_type,
                installed_version,
                measured_hash,
                hash_algorithm,
                official,
                reference,
            )
        )
    return rows
