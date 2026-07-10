"""Tests hors-ligne du vérificateur de firmware iDRAC (deux axes)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from baseline import load_baseline  # noqa: E402
from catalog import parse_catalog  # noqa: E402
from compare import (  # noqa: E402
    INTEGRITY_COMPROMISED,
    INTEGRITY_OK,
    INTEGRITY_UNVERIFIABLE,
    UPDATE_AVAILABLE,
    UPDATE_CURRENT,
    UPDATE_UNKNOWN,
    CatalogIndex,
    compare_inventory,
    compute_integrity,
    compute_update,
)
from idrac_client import (  # noqa: E402
    FirmwareEntry,
    IdracClient,
    _extract_measurement_hash,
    _integrity_target_name,
)
from matching import version_ge, version_key, versions_equal  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(__file__))
SAMPLE = os.path.join(ROOT, "sample_catalog.xml")
BASELINE = os.path.join(ROOT, "sample_baseline.json")


@pytest.fixture
def catalog():
    return parse_catalog(SAMPLE)


@pytest.fixture
def baseline():
    return load_baseline(BASELINE)


# --- Catalogue --------------------------------------------------------------
def test_parse_catalog_extracts_components(catalog):
    assert len(catalog) == 4
    bios = next(c for c in catalog if "BIOS" in c.name)
    assert bios.version == "2.16.0"
    assert bios.hash_md5 == "a1b2c3d4e5f600112233445566778899"
    assert bios.download_url.startswith("https://downloads.dell.com/")


# --- Comparaison de versions ------------------------------------------------
def test_version_key_orders_numeric_parts():
    assert version_key("2.16.0") > version_key("2.9.0")
    assert version_key("22.31.13.70") > version_key("22.31.13.7")


def test_versions_equal_and_ge():
    assert versions_equal("2.16.0", "2.16.0")
    assert version_ge("2.20.0", "2.16.0")
    assert not version_ge("2.10.0", "2.16.0")


# --- Axe mise à jour --------------------------------------------------------
def test_update_current_when_versions_match(catalog):
    index = CatalogIndex(catalog)
    official = index.latest_for("BIOS", "BIOS")
    assert compute_update("2.16.0", official) == UPDATE_CURRENT


def test_update_available_when_installed_lower(catalog):
    index = CatalogIndex(catalog)
    official = index.latest_for("BIOS", "BIOS")
    assert compute_update("2.10.0", official) == UPDATE_AVAILABLE


def test_update_unknown_without_catalog_match():
    assert compute_update("1.0", None) == UPDATE_UNKNOWN


# --- Axe intégrité (sécurité) ----------------------------------------------
def test_integrity_ok_when_hash_matches(baseline):
    ref = baseline.reference_for("BIOS", "2.10.0")
    assert ref is not None
    assert compute_integrity(ref.hash, ref) == INTEGRITY_OK


def test_integrity_compromised_same_version_different_hash(baseline):
    ref = baseline.reference_for("BIOS", "2.10.0")
    assert compute_integrity("deadbeef" * 8, ref) == INTEGRITY_COMPROMISED


def test_integrity_unverifiable_without_measured_hash(baseline):
    ref = baseline.reference_for("BIOS", "2.10.0")
    assert compute_integrity("", ref) == INTEGRITY_UNVERIFIABLE


def test_integrity_unverifiable_without_reference():
    assert compute_integrity("abc123abc123abc1", None) == INTEGRITY_UNVERIFIABLE


def test_baseline_requires_equal_version(baseline):
    # Même firmware mais version différente -> pas de référence (fichier différent).
    assert baseline.reference_for("BIOS", "2.99.0") is None


# --- Intégration des deux axes ---------------------------------------------
def test_compare_inventory_two_axes(catalog, baseline):
    ref_bios = baseline.reference_for("BIOS", "2.10.0")
    installed = [
        # Intègre (hash bon) mais mise à jour disponible.
        FirmwareEntry(name="BIOS", version="2.10.0", component_type="BIOS",
                      measured_hash=ref_bios.hash),
        # À jour MAIS compromis (même version, hash falsifié) -> cas le plus grave.
        FirmwareEntry(name="Dell PERC H755 RAID Controller", version="52.26.0-5179",
                      measured_hash="00000000" * 8),
        # Non vérifiable (pas de hash mesuré).
        FirmwareEntry(name="Broadcom NetXtreme 57414 Network Adapter", version="20.00.00.00"),
    ]
    rows = {r.name: r for r in compare_inventory(installed, catalog, baseline)}

    bios = rows["BIOS"]
    assert bios.integrity == INTEGRITY_OK
    assert bios.update == UPDATE_AVAILABLE
    assert bios.download_url  # bouton proposé

    perc = rows["Dell PERC H755 RAID Controller"]
    assert perc.integrity == INTEGRITY_COMPROMISED  # sécurité : alerte
    assert perc.update == UPDATE_CURRENT             # pourtant à jour
    assert perc.download_url == ""

    nic = rows["Broadcom NetXtreme 57414 Network Adapter"]
    assert nic.integrity == INTEGRITY_UNVERIFIABLE

    d = perc.to_dict()
    assert d["integrity_label"] == "Compromis"
    assert d["update_label"] == "À jour"


# --- Attestation SPDM (parsing best-effort) --------------------------------
def test_extract_measurement_hash_deep_search():
    detail = {
        "TargetComponentURI": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1"},
        "SPDM": {
            "IdentityAuthentication": {"ResponderAuthentication": {}},
            "Measurement": {
                "MeasurementHashingAlgorithm": "TPM_ALG_SHA_256",
                "MeasurementDataHash": "a1c2e3f405162738495a6b7c8d9e0f11",
            },
        },
    }
    h, algo = _extract_measurement_hash(detail)
    assert h == "a1c2e3f405162738495a6b7c8d9e0f11"
    assert "SHA_256" in algo


def test_integrity_target_name_from_uri():
    detail = {"TargetComponentURI": "/redfish/v1/Chassis/System.Embedded.1"}
    assert _integrity_target_name(detail) == "System.Embedded.1"


# --- racadm -----------------------------------------------------------------
def test_racadm_swinventory_parsing():
    output = """
-------------------------------------------------------------------
ElementName = BIOS
CurrentVersion = 2.10.0
Updateable = yes
-------------------------------------------------------------------
"""
    entries = IdracClient._parse_racadm_swinventory(output)
    assert len(entries) == 1
    assert entries[0].name == "BIOS"
    assert entries[0].version == "2.10.0"
