"""Attestation SPDM des périphériques iDRAC9 (Redfish ``ComponentIntegrity``).

Ciblé **iDRAC9** (firmware ≥ 6.10, **licence Datacenter requise**). Sur iDRAC9,
SPDM couvre les **contrôleurs de stockage (PERC)** et les **cartes réseau
(NIC)** — pas le BIOS ni l'iDRAC lui-même. Deux signaux sont exploités :

1. **Authenticité (identité)** — l'iDRAC vérifie le certificat matériel signé
   Dell du périphérique (détection d'une contrefaçon / d'une altération dans la
   chaîne d'approvisionnement). Disponible directement en **GET** sur la
   ressource ``ComponentIntegrity`` via ``SPDM.IdentityAuthentication`` →
   ``VerificationStatus``. C'est le signal le plus fiable, sans cryptographie
   côté client.

2. **Mesures firmware** — obtenues via l'action
   ``#ComponentIntegrity.SPDMGetSignedMeasurements`` (POST avec un *nonce*
   aléatoire, un ``SlotId`` et des ``MeasurementIndices``). La réponse contient
   ``SignedMeasurements`` (base64), ``HashingAlgorithm``, ``SigningAlgorithm``
   et ``Version``. On extrait les blocs de mesure (format DMTF DSP0274) — qui
   sont *stables* — en écartant la signature (qui varie à chaque nonce), puis
   on en dérive une empreinte comparable à une baseline connue-bonne.

⚠️ Le parsing binaire DSP0274 est conforme à la spécification mais n'a pas pu
être validé contre une unité réelle : il est **tolérant** et, surtout,
**auto-cohérent** — la baseline étant capturée avec le même extracteur, toute
divergence de mesure est détectée même si le décodage absolu diffère. Fournir
un échantillon réel de réponse permet de le figer exactement.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Optional

# Statuts d'authenticité normalisés.
AUTH_AUTHENTIC = "authentic"
AUTH_FAILED = "failed"
AUTH_UNKNOWN = "unknown"

SIGNED_MEASUREMENTS_ACTION = "#ComponentIntegrity.SPDMGetSignedMeasurements"


@dataclass
class AttestationRecord:
    """Résultat d'attestation pour un périphérique attesté par l'iDRAC."""

    target_name: str
    integrity_type: str = ""  # "SPDM" / "TPM"
    authenticity: str = AUTH_UNKNOWN
    measurement_hash: str = ""  # empreinte dérivée des blocs de mesure
    hash_algorithm: str = ""


def parse_verification_status(detail: dict) -> str:
    """Extrait l'état d'authenticité d'une ressource ComponentIntegrity.

    iDRAC9 place le résultat sous
    ``SPDM.IdentityAuthentication.ResponderAuthentication.ComponentCertificate``
    et/ou un champ ``VerificationStatus``. On recherche ce dernier de façon
    tolérante et on le normalise.
    """
    spdm = detail.get("SPDM") or {}
    ident = spdm.get("IdentityAuthentication") or {}
    status = _find_verification_status(ident)
    if status is None:
        status = _find_verification_status(detail)
    if status is None:
        return AUTH_UNKNOWN
    low = status.strip().lower()
    if low in ("success", "verified", "passed", "authentic"):
        return AUTH_AUTHENTIC
    if low in ("failed", "failure", "unverified", "invalid", "error"):
        return AUTH_FAILED
    return AUTH_UNKNOWN


def _find_verification_status(node) -> Optional[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() == "verificationstatus" and isinstance(value, str):
                return value
            found = _find_verification_status(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_verification_status(item)
            if found is not None:
                return found
    return None


def target_name(detail: dict) -> str:
    """Nom du périphérique cible d'une ressource ComponentIntegrity."""
    uri = detail.get("TargetComponentURI") or detail.get("Targets")
    if isinstance(uri, dict):
        uri = uri.get("@odata.id", "")
    if isinstance(uri, list) and uri:
        first = uri[0]
        uri = first.get("@odata.id", "") if isinstance(first, dict) else str(first)
    if uri:
        return str(uri).rstrip("/").rsplit("/", 1)[-1]
    return str(detail.get("Id") or detail.get("Name") or "")


def action_target(detail: dict, action_name: str) -> str:
    """URI ``target`` d'une action Redfish nommée, si exposée."""
    actions = detail.get("Actions") or {}
    action = actions.get(action_name) or {}
    return action.get("target", "")


def signed_measurements_action_target(detail: dict) -> str:
    """URI de l'action SPDMGetSignedMeasurements, si exposée."""
    return action_target(detail, SIGNED_MEASUREMENTS_ACTION)


def make_nonce(num_bytes: int = 32) -> str:
    """Nonce aléatoire hex (le périphérique le signe avec les mesures)."""
    return os.urandom(num_bytes).hex()


def extract_measurement_digest(signed_measurements_b64: str, hashing_algorithm: str = "") -> str:
    """Dérive une empreinte stable des blocs de mesure SPDM (DSP0274).

    Décode la base64 puis parcourt les blocs de mesure
    ``[Index(1) | Spec(1) | Size(2, little-endian) | Value(Size)]`` tant qu'ils
    sont bien formés, en écartant la signature finale (variable). Retourne le
    SHA-256 de la concaténation ``index:value`` triée, ou ``""`` si aucun bloc
    exploitable n'est trouvé.
    """
    import base64

    try:
        raw = base64.b64decode(signed_measurements_b64, validate=False)
    except Exception:
        return ""
    blocks = _parse_measurement_blocks(raw)
    if not blocks:
        return ""
    normalized = "|".join(f"{idx}:{val.hex()}" for idx, val in sorted(blocks))
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def _parse_measurement_blocks(raw: bytes) -> list[tuple[int, bytes]]:
    blocks: list[tuple[int, bytes]] = []
    offset = 0
    n = len(raw)
    while offset + 4 <= n:
        index = raw[offset]
        size = struct.unpack_from("<H", raw, offset + 2)[0]
        end = offset + 4 + size
        # Bloc plausible : taille non nulle et tenant dans le tampon.
        if size == 0 or end > n or size > 4096:
            break
        value = raw[offset + 4 : end]
        blocks.append((index, value))
        offset = end
        # Les indices de mesure DSP0274 vont de 1 à 254 ; garde-fou.
        if index == 0 or index > 254:
            break
    return blocks
