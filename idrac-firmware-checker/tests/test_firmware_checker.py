"""Tests hors-ligne du vérificateur de firmware iDRAC."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from catalog import parse_catalog  # noqa: E402
from compare import (  # noqa: E402
    STATUS_OK,
    STATUS_OUTDATED,
    STATUS_UNKNOWN,
    CatalogIndex,
    _status_for,
    _version_key,
    build_row,
    compare_inventory,
)
from idrac_client import FirmwareEntry, IdracClient  # noqa: E402

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_catalog.xml")


@pytest.fixture
def catalog():
    return parse_catalog(SAMPLE)


def test_parse_catalog_extracts_components(catalog):
    assert len(catalog) == 4
    bios = next(c for c in catalog if "BIOS" in c.name)
    assert bios.version == "2.16.0"
    assert bios.hash_md5 == "a1b2c3d4e5f600112233445566778899"
    assert bios.download_url.startswith("https://downloads.dell.com/")


def test_version_key_orders_numeric_parts():
    assert _version_key("2.16.0") > _version_key("2.9.0")
    assert _version_key("22.31.13.70") > _version_key("22.31.13.7")


def test_status_ok_when_versions_match():
    assert _status_for("2.16.0", "2.16.0") == STATUS_OK


def test_status_outdated_when_installed_lower():
    assert _status_for("2.10.0", "2.16.0") == STATUS_OUTDATED


def test_status_ok_when_installed_higher():
    assert _status_for("2.20.0", "2.16.0") == STATUS_OK


def test_status_unknown_when_missing_version():
    assert _status_for("", "2.16.0") == STATUS_UNKNOWN


def test_compare_inventory_flags_outdated_bios(catalog):
    installed = [
        FirmwareEntry(name="BIOS", version="2.10.0", component_type="BIOS"),
        FirmwareEntry(name="Integrated Dell Remote Access Controller", version="7.10.30.00"),
    ]
    rows = compare_inventory(installed, catalog)
    by_name = {r.name: r for r in rows}

    bios = by_name["BIOS"]
    assert bios.status == STATUS_OUTDATED
    assert bios.official_version == "2.16.0"
    assert bios.download_url  # bouton de mise à jour proposé
    assert bios.reference_hash == "a1b2c3d4e5f600112233445566778899"

    idrac = by_name["Integrated Dell Remote Access Controller"]
    assert idrac.status == STATUS_OK
    assert idrac.download_url == ""


def test_unknown_component_has_no_match(catalog):
    installed = [FirmwareEntry(name="Composant totalement inexistant XYZ", version="1.0")]
    rows = compare_inventory(installed, catalog)
    assert rows[0].status == STATUS_UNKNOWN
    assert rows[0].matched is False


def test_catalog_index_best_match(catalog):
    index = CatalogIndex(catalog)
    match = index.best_match("Broadcom NetXtreme 57414")
    assert match is not None
    assert "Broadcom" in match.name


def test_racadm_swinventory_parsing():
    output = """
-------------------------------------------------------------------
ElementName = BIOS
FQDD = BIOS.Setup.1-1
CurrentVersion = 2.10.0
Updateable = yes
-------------------------------------------------------------------
ElementName = Integrated Dell Remote Access Controller
CurrentVersion = 7.00.00.00
Updateable = yes
-------------------------------------------------------------------
"""
    entries = IdracClient._parse_racadm_swinventory(output)
    assert len(entries) == 2
    assert entries[0].name == "BIOS"
    assert entries[0].version == "2.10.0"
    assert entries[0].updateable is True


def test_build_row_unknown_official_none():
    row = build_row("Truc", "", "1.0", None)
    assert row.status == STATUS_UNKNOWN
    assert row.to_dict()["status_label"] == "Inconnu"
