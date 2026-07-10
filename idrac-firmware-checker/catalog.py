"""Téléchargement et analyse du catalogue officiel Dell.

Le catalogue Dell (``Catalog.xml``, distribué compressé en ``Catalog.xml.gz``)
liste tous les paquets de mise à jour (DUP) publiés par Dell. Chaque paquet est
un élément ``SoftwareComponent`` portant notamment :

* ``vendorVersion`` / ``dellVersion`` : la version officielle du firmware,
* ``hashMD5`` : le hash MD5 **du fichier DUP téléchargeable**,
* ``path`` : le chemin relatif de téléchargement sous ``downloads.dell.com``,
* un sous-élément ``ComponentType`` et un libellé ``Name/Display``.

⚠️ Important : ``hashMD5`` est le hash du *paquet de mise à jour*, pas du
firmware en cours d'exécution. On l'affiche comme *hash de référence* mais la
détection « intègre / non conforme » repose sur la comparaison de version
(voir ``compare.py``), seule information exploitable côté iDRAC.

Le vrai catalogue pèse plusieurs centaines de Mo une fois décompressé : on
utilise ``iterparse`` pour le lire en flux sans tout charger en mémoire.
"""

from __future__ import annotations

import gzip
import io
import os
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Iterable, Optional

import requests

DELL_CATALOG_URL = "https://downloads.dell.com/catalog/Catalog.xml.gz"
DELL_DOWNLOAD_BASE = "https://downloads.dell.com/"


class CatalogError(RuntimeError):
    """Erreur de téléchargement ou d'analyse du catalogue."""


@dataclass
class CatalogComponent:
    """Un paquet de mise à jour officiel Dell."""

    name: str
    version: str
    component_type: str = ""
    hash_md5: str = ""
    path: str = ""
    release_date: str = ""
    supported_device_ids: list[str] = field(default_factory=list)

    @property
    def download_url(self) -> str:
        if not self.path:
            return ""
        return DELL_DOWNLOAD_BASE + self.path.lstrip("/")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "component_type": self.component_type,
            "hash_md5": self.hash_md5,
            "path": self.path,
            "download_url": self.download_url,
            "release_date": self.release_date,
            "supported_device_ids": self.supported_device_ids,
        }


def _strip_ns(tag: str) -> str:
    """Retire l'espace de noms XML : ``{ns}Tag`` -> ``Tag``."""
    return tag.rsplit("}", 1)[-1]


def download_catalog(
    url: str = DELL_CATALOG_URL,
    *,
    cache_path: Optional[str] = None,
    max_age_seconds: int = 24 * 3600,
    timeout: int = 120,
) -> bytes:
    """Télécharge le catalogue (décompressé) et le met en cache sur disque.

    Retourne le contenu XML décompressé en octets.
    """
    if cache_path and os.path.exists(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        if age < max_age_seconds and os.path.getsize(cache_path) > 0:
            with open(cache_path, "rb") as fh:
                return fh.read()

    try:
        resp = requests.get(url, timeout=timeout, stream=True)
    except requests.RequestException as exc:
        raise CatalogError(f"Téléchargement du catalogue impossible : {exc}") from exc
    if resp.status_code >= 400:
        raise CatalogError(f"Catalogue indisponible (HTTP {resp.status_code}).")

    raw = resp.content
    data = _maybe_gunzip(raw, url)

    if cache_path:
        os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
        with open(cache_path, "wb") as fh:
            fh.write(data)
    return data


def _maybe_gunzip(raw: bytes, url: str) -> bytes:
    is_gzip = url.endswith(".gz") or raw[:2] == b"\x1f\x8b"
    if not is_gzip:
        return raw
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            return gz.read()
    except OSError as exc:
        raise CatalogError(f"Décompression du catalogue impossible : {exc}") from exc


def parse_catalog(source) -> list[CatalogComponent]:
    """Analyse un catalogue Dell en flux.

    ``source`` peut être un chemin de fichier, des octets, ou un objet fichier.
    """
    if isinstance(source, (bytes, bytearray)):
        stream = io.BytesIO(source)
    elif isinstance(source, str):
        stream = open(source, "rb")  # noqa: SIM115 - fermé plus bas
    else:
        stream = source

    components: list[CatalogComponent] = []
    try:
        for _event, elem in ET.iterparse(stream, events=("end",)):
            if _strip_ns(elem.tag) != "SoftwareComponent":
                continue
            components.append(_parse_component(elem))
            elem.clear()  # Libère la mémoire au fil de l'eau.
    except ET.ParseError as exc:
        raise CatalogError(f"Catalogue XML invalide : {exc}") from exc
    finally:
        if isinstance(source, str):
            stream.close()
    return components


def _parse_component(elem: ET.Element) -> CatalogComponent:
    attrib = elem.attrib
    version = attrib.get("vendorVersion") or attrib.get("dellVersion") or ""
    hash_md5 = (attrib.get("hashMD5") or "").lower()
    path = attrib.get("path") or ""
    release_date = attrib.get("dateTime") or attrib.get("releaseDate") or ""

    name = ""
    component_type = ""
    device_ids: list[str] = []

    for child in elem:
        tag = _strip_ns(child.tag)
        if tag == "Name":
            display = child.find("./{*}Display")
            if display is None:
                display = next((c for c in child if _strip_ns(c.tag) == "Display"), None)
            if display is not None and display.text:
                name = display.text.strip()
        elif tag == "ComponentType":
            component_type = (child.attrib.get("value") or "").strip()
            if not component_type:
                disp = next((c for c in child if _strip_ns(c.tag) == "Display"), None)
                if disp is not None and disp.text:
                    component_type = disp.text.strip()
        elif tag == "SupportedDevices":
            for dev in child.iter():
                if _strip_ns(dev.tag) == "Device":
                    dev_id = dev.attrib.get("componentID") or dev.attrib.get("id")
                    if dev_id:
                        device_ids.append(dev_id.strip())

    return CatalogComponent(
        name=name or attrib.get("name", "Inconnu"),
        version=version,
        component_type=component_type,
        hash_md5=hash_md5,
        path=path,
        release_date=release_date,
        supported_device_ids=device_ids,
    )


def load_catalog(
    *,
    url: str = DELL_CATALOG_URL,
    cache_path: Optional[str] = None,
    local_path: Optional[str] = None,
    max_age_seconds: int = 24 * 3600,
) -> list[CatalogComponent]:
    """Charge le catalogue depuis un fichier local ou en le téléchargeant."""
    if local_path:
        if not os.path.exists(local_path):
            raise CatalogError(f"Catalogue local introuvable : {local_path}")
        return parse_catalog(local_path)
    data = download_catalog(url, cache_path=cache_path, max_age_seconds=max_age_seconds)
    return parse_catalog(data)
