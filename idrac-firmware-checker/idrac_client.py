"""Client de connexion à un iDRAC Dell.

Deux transports sont pris en charge :

1. **Redfish** (par défaut) — API HTTP standard exposée par l'iDRAC. On lit
   la collection ``/redfish/v1/UpdateService/FirmwareInventory`` qui liste les
   firmwares *installés* et *disponibles*. On ne conserve que les entrées
   installées.
2. **racadm** (repli) — invocation de la CLI Dell ``racadm`` si elle est
   présente sur la machine hôte. Utile lorsque Redfish est désactivé.

Aucune de ces sources n'expose de *hash* du firmware réellement en cours
d'exécution : Redfish ne renvoie qu'un nom, une version et un identifiant
logiciel. La vérification d'intégrité se fait donc par comparaison de version
avec le catalogue officiel Dell (voir ``catalog.py``).
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

import spdm
import tpm

try:  # Neutralise l'avertissement de certificat auto-signé de l'iDRAC.
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover - urllib3 est fourni par requests
    pass


class IdracError(RuntimeError):
    """Erreur de connexion ou de dialogue avec l'iDRAC."""


@dataclass
class FirmwareEntry:
    """Un firmware installé remonté par l'iDRAC.

    ``measured_hash`` est l'empreinte du firmware *en cours d'exécution*,
    obtenue par attestation SPDM (``ComponentIntegrity``) quand la plateforme
    le supporte. Vide sinon → l'intégrité sera « non vérifiable ».
    """

    name: str
    version: str
    component_type: str = ""
    software_id: str = ""
    updateable: bool = False
    measured_hash: str = ""
    hash_algorithm: str = ""
    authenticity: str = ""  # authentic / failed / unknown (attestation SPDM)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "component_type": self.component_type,
            "software_id": self.software_id,
            "updateable": self.updateable,
            "measured_hash": self.measured_hash,
            "hash_algorithm": self.hash_algorithm,
            "authenticity": self.authenticity,
        }


class IdracClient:
    """Dialogue avec un iDRAC via Redfish (ou racadm en repli)."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        verify_ssl: bool = False,
        timeout: int = 20,
    ) -> None:
        self.host = host.strip().rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    # API publique
    # ------------------------------------------------------------------ #
    def get_firmware_inventory(self, *, transport: str = "redfish") -> list[FirmwareEntry]:
        """Retourne la liste des firmwares installés.

        ``transport`` vaut ``"redfish"``, ``"racadm"`` ou ``"auto"`` (Redfish
        puis repli racadm en cas d'échec).
        """
        if transport == "redfish":
            return self._inventory_redfish()
        if transport == "racadm":
            return self._inventory_racadm()
        if transport == "auto":
            try:
                return self._inventory_redfish()
            except IdracError:
                if shutil.which("racadm"):
                    return self._inventory_racadm()
                raise
        raise ValueError(f"Transport inconnu : {transport!r}")

    # ------------------------------------------------------------------ #
    # Transport Redfish
    # ------------------------------------------------------------------ #
    def _base_url(self) -> str:
        host = self.host
        if not host.startswith(("http://", "https://")):
            host = "https://" + host
        return host

    def _get_json(self, path: str) -> dict:
        url = self._base_url() + path
        try:
            resp = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers={"Accept": "application/json"},
            )
        except requests.exceptions.SSLError as exc:
            raise IdracError(
                "Échec de la vérification TLS. L'iDRAC utilise souvent un "
                "certificat auto-signé : décochez la vérification TLS."
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise IdracError(f"Connexion impossible à {self.host} : {exc}") from exc
        except requests.exceptions.Timeout as exc:
            raise IdracError(f"Délai dépassé en contactant {self.host}.") from exc

        if resp.status_code == 401:
            raise IdracError("Identifiants refusés par l'iDRAC (401).")
        if resp.status_code == 404:
            raise IdracError(f"Ressource Redfish introuvable : {path} (404).")
        if resp.status_code >= 400:
            raise IdracError(f"Erreur Redfish {resp.status_code} sur {path}.")
        try:
            return resp.json()
        except ValueError as exc:
            raise IdracError("Réponse Redfish non JSON (Redfish désactivé ?).") from exc

    def _inventory_redfish(self) -> list[FirmwareEntry]:
        collection = self._get_json("/redfish/v1/UpdateService/FirmwareInventory")
        members = collection.get("Members", [])
        entries: list[FirmwareEntry] = []
        for member in members:
            odata_id = member.get("@odata.id")
            if not odata_id:
                continue
            # On ne garde que les firmwares installés (préfixe "Installed-").
            # Les entrées "Available-*" correspondent à des paquets en attente.
            if "/Installed-" not in odata_id and "Installed" not in odata_id:
                continue
            detail = self._get_json(odata_id)
            entries.append(self._parse_redfish_entry(detail))

        if not entries:
            # Certains iDRAC ne préfixent pas par "Installed-" : on relit tout.
            for member in members:
                odata_id = member.get("@odata.id")
                if not odata_id:
                    continue
                detail = self._get_json(odata_id)
                entry = self._parse_redfish_entry(detail)
                if entry.version:
                    entries.append(entry)
        return entries

    @staticmethod
    def _parse_redfish_entry(detail: dict) -> FirmwareEntry:
        name = detail.get("Name") or detail.get("Id") or "Inconnu"
        version = detail.get("Version") or ""
        software_id = detail.get("SoftwareId") or ""
        updateable = bool(detail.get("Updateable", False))
        # Dell expose parfois un type via Oem/ComponentType.
        oem = detail.get("Oem", {}) or {}
        dell = oem.get("Dell", {}) if isinstance(oem, dict) else {}
        component_type = ""
        if isinstance(dell, dict):
            dell_soft = dell.get("DellSoftwareInventory", {})
            if isinstance(dell_soft, dict):
                component_type = dell_soft.get("ComponentType", "") or ""
        return FirmwareEntry(
            name=str(name),
            version=str(version),
            component_type=str(component_type),
            software_id=str(software_id),
            updateable=updateable,
            raw=detail,
        )

    # ------------------------------------------------------------------ #
    # Attestation SPDM iDRAC9 (Redfish ComponentIntegrity)
    # ------------------------------------------------------------------ #
    def get_attestation_records(self, *, fetch_measurements: bool = True) -> list[spdm.AttestationRecord]:
        """Attestation SPDM des périphériques (PERC/NIC) sur iDRAC9.

        Interroge ``/redfish/v1/ComponentIntegrity`` : pour chaque périphérique
        attesté, on lit l'**authenticité** (identité SPDM vérifiée par l'iDRAC)
        et, si ``fetch_measurements``, on invoque l'action
        ``SPDMGetSignedMeasurements`` pour dériver une empreinte de mesure.

        Best-effort et silencieux : endpoint absent (licence/firmware/support
        manquant) → liste vide → intégrité « non vérifiable ».
        """
        records: list[spdm.AttestationRecord] = []
        try:
            collection = self._get_json("/redfish/v1/ComponentIntegrity")
        except IdracError:
            return records
        for member in collection.get("Members", []):
            odata_id = member.get("@odata.id")
            if not odata_id:
                continue
            try:
                detail = self._get_json(odata_id)
            except IdracError:
                continue
            integrity_type = (detail.get("ComponentIntegrityType", "") or "").upper()
            record = spdm.AttestationRecord(
                target_name=spdm.target_name(detail),
                integrity_type=integrity_type,
                authenticity=spdm.parse_verification_status(detail),
            )
            if integrity_type == "TPM":
                # Mesures BIOS/UEFI : digests PCR exposés en GET, sinon action.
                digest, algo = tpm.extract_pcr_digest(detail)
                if not digest and fetch_measurements:
                    action = spdm.action_target(detail, tpm.TPM_SIGNED_MEASUREMENTS_ACTION)
                    if action:
                        digest, algo = self._signed_measurement_digest(action, kind="tpm")
                record.measurement_hash = digest
                record.hash_algorithm = algo
            elif fetch_measurements:
                action_target = spdm.signed_measurements_action_target(detail)
                if action_target:
                    digest, algo = self._signed_measurement_digest(action_target)
                    record.measurement_hash = digest
                    record.hash_algorithm = algo
            records.append(record)
        return records

    def _signed_measurement_digest(self, action_target: str, kind: str = "spdm") -> tuple[str, str]:
        """Appelle *GetSignedMeasurements et dérive une empreinte de mesure.

        ``kind`` (``"spdm"`` / ``"tpm"``) est informatif : les deux réponses
        exposent ``SignedMeasurements`` (base64) que l'on décode en blocs de
        mesure via le même extracteur, en écartant la signature.
        """
        payload = {"Nonce": spdm.make_nonce(), "SlotId": 0}
        url = self._base_url() + action_target
        try:
            resp = requests.post(
                url,
                json=payload,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
            )
        except requests.RequestException:
            return "", ""
        if resp.status_code >= 400:
            return "", ""
        try:
            data = resp.json()
        except ValueError:
            return "", ""
        algo = data.get("HashingAlgorithm", "") or ""
        digest = spdm.extract_measurement_digest(data.get("SignedMeasurements", "") or "", algo)
        return digest, algo

    def enrich_with_attestation(self, entries: list[FirmwareEntry]) -> None:
        """Complète l'inventaire avec l'authenticité et le hash mesuré.

        SPDM → périphériques (PERC/NIC), rapproché par nom de cible.
        TPM  → BIOS/UEFI (mesures PCR), rattaché à l'entrée BIOS.
        """
        records = self.get_attestation_records()
        if not records:
            return
        tpm_records = [r for r in records if r.integrity_type == "TPM"]
        device_records = [r for r in records if r.integrity_type != "TPM"]
        for entry in entries:
            record = None
            if _is_bios(entry) and tpm_records:
                record = tpm_records[0]
            if record is None:
                record = _match_attestation(entry.name, device_records)
            if record is None:
                continue
            entry.authenticity = record.authenticity
            if record.measurement_hash:
                entry.measured_hash = record.measurement_hash
                entry.hash_algorithm = record.hash_algorithm

    # ------------------------------------------------------------------ #
    # Transport racadm (repli)
    # ------------------------------------------------------------------ #
    def _inventory_racadm(self) -> list[FirmwareEntry]:
        if not shutil.which("racadm"):
            raise IdracError("La CLI 'racadm' est introuvable sur cet hôte.")
        cmd = [
            "racadm",
            "-r",
            self.host,
            "-u",
            self.username,
            "-p",
            self.password,
            "--nocertwarn",
            "swinventory",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise IdracError("Délai dépassé lors de l'appel racadm.") from exc
        except OSError as exc:
            raise IdracError(f"Impossible d'exécuter racadm : {exc}") from exc

        if proc.returncode != 0:
            raise IdracError(
                f"racadm a échoué (code {proc.returncode}) : {proc.stderr.strip()}"
            )
        return self._parse_racadm_swinventory(proc.stdout)

    @staticmethod
    def _parse_racadm_swinventory(output: str) -> list[FirmwareEntry]:
        """Parse la sortie texte de ``racadm swinventory``.

        Les blocs sont séparés par des lignes de tirets, chaque bloc portant
        des paires ``Clé = Valeur`` (ElementName, CurrentVersion, ...).
        """
        entries: list[FirmwareEntry] = []
        current: dict[str, str] = {}

        def flush() -> None:
            if not current:
                return
            name = current.get("ElementName") or current.get("FQDD") or "Inconnu"
            version = current.get("CurrentVersion") or current.get("Version") or ""
            if version:
                entries.append(
                    FirmwareEntry(
                        name=name,
                        version=version,
                        component_type=current.get("ComponentType", ""),
                        updateable=current.get("Updateable", "").lower() == "yes",
                        raw=dict(current),
                    )
                )

        for line in output.splitlines():
            stripped = line.strip()
            if set(stripped) <= {"-"} and stripped:
                flush()
                current = {}
                continue
            if "=" in stripped:
                key, _, value = stripped.partition("=")
                current[key.strip()] = value.strip()
        flush()
        return entries


def _is_bios(entry: "FirmwareEntry") -> bool:
    return (entry.component_type or "").upper() == "BIOS" or "bios" in (entry.name or "").lower()


def _match_attestation(name: str, records: list) -> Optional[object]:
    """Rapproche une entrée d'inventaire d'un enregistrement d'attestation
    (rapprochement par sous-chaîne de nom de cible)."""
    low = name.lower()
    for record in records:
        target = (record.target_name or "").lower()
        if target and (target in low or low in target):
            return record
    return None


def parse_installed_from_racadm_xml(xml_text: str) -> list[FirmwareEntry]:
    """Utilitaire : parse un export XML de firmware (``racadm get -f ...``).

    Fourni pour faciliter les tests hors-ligne.
    """
    root = ET.fromstring(xml_text)
    entries: list[FirmwareEntry] = []
    for comp in root.iter("INSTALLEDDEVICE"):
        name = comp.findtext("NAME", default="Inconnu")
        version = comp.findtext("VERSION", default="")
        entries.append(FirmwareEntry(name=name, version=version))
    return entries
