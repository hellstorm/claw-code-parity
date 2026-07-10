"""Attestation TPM/PCR du BIOS/UEFI (Redfish ``ComponentIntegrity`` type TPM).

Le BIOS n'est pas couvert par SPDM sur iDRAC9. La voie standard pour attester
son intégrité est le **TPM** : au démarrage, l'UEFI mesure le firmware dans les
registres **PCR** (PCR0–7 couvrent le BIOS/UEFI). iDRAC9 peut exposer ces
mesures via une ressource ``ComponentIntegrity`` de type ``TPM`` (mécanisme
DMTF, jumeau du type ``SPDM``), avec l'action
``#ComponentIntegrity.TPMGetSignedMeasurements``.

On dérive une empreinte **stable** des digests PCR pertinents, comparée à un
**golden PCR** de la baseline (l'attendu pour un BIOS de confiance à version
donnée). Un digest différent à version égale = BIOS altéré → **Compromis**.

⚠️ Comme pour SPDM, le format exact exposé par iDRAC9 n'a pas pu être validé
contre une unité réelle : l'extraction est **tolérante** et **auto-cohérente**
(la baseline étant capturée avec le même extracteur). Fournir un échantillon
réel de réponse permet de figer le décodage exactement.
"""

from __future__ import annotations

import hashlib
import re

# PCR mesurant le BIOS/UEFI (firmware, config, Secure Boot…). On se concentre
# sur PCR0–7 (chaîne de démarrage plateforme).
BIOS_PCR_INDICES = tuple(range(0, 8))

TPM_SIGNED_MEASUREMENTS_ACTION = "#ComponentIntegrity.TPMGetSignedMeasurements"

_HEX_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{40,128}$")  # SHA-1 (40) … SHA-512 (128)


def extract_pcr_digest(detail: dict, pcr_indices: tuple = BIOS_PCR_INDICES) -> tuple[str, str]:
    """Empreinte stable dérivée des digests PCR d'une ressource TPM.

    Parcourt la structure à la recherche de couples ``(index PCR, digest)`` et
    de digests de mesure, ne retient que les PCR pertinents (BIOS/UEFI), puis
    calcule un SHA-256 de la concaténation triée ``index:digest``.
    Retourne ``("", "")`` si rien d'exploitable n'est trouvé.
    """
    pairs: dict[int, str] = {}
    algo = ""
    algo_holder = [algo]
    _walk(detail, pairs, algo_holder, set(pcr_indices))
    if not pairs:
        return "", ""
    normalized = "|".join(f"{idx}:{pairs[idx].lower()}" for idx in sorted(pairs))
    return hashlib.sha256(normalized.encode("ascii")).hexdigest(), algo_holder[0]


def _walk(node, pairs: dict, algo_holder: list, wanted: set) -> None:
    if isinstance(node, dict):
        idx = _read_pcr_index(node)
        digest = _read_digest(node)
        if idx is not None and digest and (not wanted or idx in wanted):
            pairs.setdefault(idx, digest)
        for key, value in node.items():
            kl = key.lower()
            if ("hashalgorithm" in kl or kl in ("algorithm", "hashingalgorithm")) and isinstance(value, str):
                if value and not algo_holder[0]:
                    algo_holder[0] = value
            _walk(value, pairs, algo_holder, wanted)
    elif isinstance(node, list):
        for item in node:
            _walk(item, pairs, algo_holder, wanted)


def _read_pcr_index(node: dict):
    for key, value in node.items():
        kl = key.lower()
        if kl in ("pcr", "pcrindex", "index", "measurementindex"):
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
    return None


def _read_digest(node: dict):
    for key, value in node.items():
        kl = key.lower()
        if ("digest" in kl or "measurement" in kl or "pcrvalue" in kl) and isinstance(value, str):
            candidate = value.strip().replace("0x", "")
            if _HEX_DIGEST_RE.match(candidate):
                return candidate
    return None
