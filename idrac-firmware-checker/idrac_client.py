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

try:  # Neutralise l'avertissement de certificat auto-signé de l'iDRAC.
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover - urllib3 est fourni par requests
    pass


class IdracError(RuntimeError):
    """Erreur de connexion ou de dialogue avec l'iDRAC."""


@dataclass
class FirmwareEntry:
    """Un firmware installé remonté par l'iDRAC."""

    name: str
    version: str
    component_type: str = ""
    software_id: str = ""
    updateable: bool = False
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "component_type": self.component_type,
            "software_id": self.software_id,
            "updateable": self.updateable,
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
