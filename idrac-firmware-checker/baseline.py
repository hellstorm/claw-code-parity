"""Base de référence des empreintes « connues-bonnes » de firmware.

Le catalogue Dell fournit le hash du *paquet* de mise à jour (DUP), pas celui
du firmware en cours d'exécution. Pour vérifier l'intégrité du firmware
installé — le point de sécurité primordial : **à version égale, un hash
différent = compromis** — on compare le hash *mesuré* du firmware à une
empreinte de référence issue d'une capture connue-bonne (« baseline »).

La baseline est établie une fois sur un hôte de confiance, puis réutilisée
pour détecter toute divergence sur les autres hôtes ou dans le temps. Format
JSON :

    [
      {"name": "BIOS", "version": "2.16.0",
       "hash": "…", "algorithm": "SHA256"},
      …
    ]

Le rapprochement exige **l'égalité de version** (même « nom de fichier ») :
comparer des hash de versions différentes n'aurait aucun sens.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from matching import normalize_hash, similarity, versions_equal


@dataclass
class BaselineEntry:
    name: str
    version: str
    hash: str
    algorithm: str = ""

    @property
    def normalized_hash(self) -> str:
        return normalize_hash(self.hash)


class Baseline:
    """Ensemble d'empreintes de référence, interrogeable par nom + version."""

    def __init__(self, entries: list[BaselineEntry]) -> None:
        self.entries = entries

    def __len__(self) -> int:
        return len(self.entries)

    def reference_for(self, name: str, version: str) -> Optional[BaselineEntry]:
        """Empreinte de référence pour ce firmware **à version identique**.

        Retourne ``None`` si aucune entrée connue-bonne ne correspond au couple
        (nom comparable, version exacte) — auquel cas l'intégrité est « non
        vérifiable ».
        """
        best: Optional[BaselineEntry] = None
        best_score = 0.0
        for entry in self.entries:
            if not versions_equal(entry.version, version):
                continue
            score = similarity(name, entry.name)
            if score > best_score:
                best_score = score
                best = entry
        return best if best_score >= 0.5 else None


def load_baseline(path: Optional[str]) -> Baseline:
    """Charge une baseline JSON ; retourne une baseline vide si ``path`` est
    absent ou introuvable."""
    if not path or not os.path.exists(path):
        return Baseline([])
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    entries: list[BaselineEntry] = []
    for item in data:
        entries.append(
            BaselineEntry(
                name=item.get("name", ""),
                version=item.get("version", ""),
                hash=item.get("hash", ""),
                algorithm=item.get("algorithm", ""),
            )
        )
    return Baseline(entries)
