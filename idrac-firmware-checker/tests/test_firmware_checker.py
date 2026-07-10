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
import catalog as catalog_mod  # noqa: E402
from idrac_client import FirmwareEntry, IdracClient, _is_bios, _match_attestation  # noqa: E402
from matching import version_ge, version_key, versions_equal  # noqa: E402
import spdm  # noqa: E402
import tpm  # noqa: E402

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


def test_integrity_compromised_when_authenticity_failed(baseline):
    # Échec d'authentification de l'identité SPDM -> compromis, quelles que
    # soient les mesures.
    ref = baseline.reference_for("BIOS", "2.10.0")
    assert compute_integrity(ref.hash, ref, authenticity="failed") == INTEGRITY_COMPROMISED


def test_integrity_ok_when_authentic_and_hash_matches(baseline):
    ref = baseline.reference_for("BIOS", "2.10.0")
    assert compute_integrity(ref.hash, ref, authenticity="authentic") == INTEGRITY_OK


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


# --- Attestation SPDM iDRAC9 ------------------------------------------------
def test_parse_verification_status_success():
    detail = {
        "SPDM": {
            "IdentityAuthentication": {
                "ResponderAuthentication": {"VerificationStatus": "Success"}
            }
        }
    }
    assert spdm.parse_verification_status(detail) == spdm.AUTH_AUTHENTIC


def test_parse_verification_status_failed():
    detail = {"SPDM": {"IdentityAuthentication": {"VerificationStatus": "Failed"}}}
    assert spdm.parse_verification_status(detail) == spdm.AUTH_FAILED


def test_parse_verification_status_unknown_when_absent():
    assert spdm.parse_verification_status({"SPDM": {}}) == spdm.AUTH_UNKNOWN


def test_target_name_from_component_uri():
    detail = {"TargetComponentURI": {"@odata.id": "/redfish/v1/Chassis/RAID.Slot.1-1"}}
    assert spdm.target_name(detail) == "RAID.Slot.1-1"


def test_signed_measurements_action_target():
    detail = {
        "Actions": {
            "#ComponentIntegrity.SPDMGetSignedMeasurements": {
                "target": "/redfish/v1/ComponentIntegrity/1/Actions/"
                "ComponentIntegrity.SPDMGetSignedMeasurements"
            }
        }
    }
    assert spdm.signed_measurements_action_target(detail).endswith("SPDMGetSignedMeasurements")


def test_extract_measurement_digest_is_stable_ignoring_signature():
    import base64
    import struct

    # Deux blocs de mesure DSP0274 : [index(1)|spec(1)|size(2 LE)|value].
    def block(index, value):
        return bytes([index, 0x01]) + struct.pack("<H", len(value)) + value

    blocks = block(1, b"\xaa" * 48) + block(2, b"\xbb" * 48)
    # Deux « signatures » différentes concaténées après les blocs.
    sig_a = b"\x00" * 4 + b"signatureA-variable-part"
    sig_b = b"\x00" * 4 + b"signatureB-totally-other"
    digest_a = spdm.extract_measurement_digest(base64.b64encode(blocks + sig_a).decode())
    digest_b = spdm.extract_measurement_digest(base64.b64encode(blocks + sig_b).decode())
    assert digest_a and digest_a == digest_b  # stable malgré la signature variable

    # Une mesure altérée change l'empreinte.
    tampered = block(1, b"\xaa" * 48) + block(2, b"\xcc" * 48)
    assert spdm.extract_measurement_digest(base64.b64encode(tampered + sig_a).decode()) != digest_a


def test_extract_measurement_digest_empty_on_garbage():
    assert spdm.extract_measurement_digest("not base64 %%%") == ""


def test_match_attestation_by_substring():
    records = [spdm.AttestationRecord(target_name="RAID.Slot.1-1", authenticity="authentic")]
    m = _match_attestation("Dell PERC H755 RAID.Slot.1-1 Controller", records)
    assert m is not None and m.authenticity == "authentic"


# --- Attestation TPM/PCR (BIOS) --------------------------------------------
def _tpm_detail(pcr_values):
    return {
        "ComponentIntegrityType": "TPM",
        "TargetComponentURI": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1"},
        "TPM": {
            "IdentityAuthentication": {"VerificationStatus": "Success"},
            "MeasurementSet": {
                "HashAlgorithm": "SHA256",
                "Measurements": [
                    {"PCRIndex": idx, "Digest": val} for idx, val in pcr_values.items()
                ],
            },
        },
    }


def test_tpm_pcr_digest_stable_and_sensitive():
    good = {0: "aa" * 32, 1: "bb" * 32, 7: "cc" * 32}
    d1, algo = tpm.extract_pcr_digest(_tpm_detail(good))
    d2, _ = tpm.extract_pcr_digest(_tpm_detail(dict(good)))
    assert d1 and d1 == d2  # déterministe
    assert algo == "SHA256"
    tampered = {**good, 0: "dd" * 32}  # PCR0 (BIOS) altéré
    d3, _ = tpm.extract_pcr_digest(_tpm_detail(tampered))
    assert d3 != d1


def test_tpm_pcr_digest_ignores_out_of_range_pcr():
    # Un PCR hors périmètre BIOS (ex. 15) ne doit pas entrer dans l'empreinte.
    base = {0: "aa" * 32}
    d_base, _ = tpm.extract_pcr_digest(_tpm_detail(base))
    d_extra, _ = tpm.extract_pcr_digest(_tpm_detail({**base, 15: "ee" * 32}))
    assert d_base == d_extra


def test_tpm_pcr_digest_empty_when_absent():
    assert tpm.extract_pcr_digest({"TPM": {}}) == ("", "")


def test_is_bios_detection():
    assert _is_bios(FirmwareEntry(name="BIOS", version="2.10.0", component_type="BIOS"))
    assert _is_bios(FirmwareEntry(name="System BIOS", version="1.0"))
    assert not _is_bios(FirmwareEntry(name="Broadcom NIC", version="1.0"))


# --- Vérification du paquet DUP --------------------------------------------
class _FakeResp:
    def __init__(self, chunks, status_code=200):
        self._chunks = chunks
        self.status_code = status_code

    def iter_content(self, chunk_size):
        for c in self._chunks:
            yield c

    def close(self):
        pass


def test_verify_dup_conforme(monkeypatch):
    import hashlib

    payload = b"DELL-DUP-CONTENT-EXAMPLE" * 100
    md5 = hashlib.md5(payload).hexdigest()
    monkeypatch.setattr(catalog_mod.requests, "get", lambda *a, **k: _FakeResp([payload]))
    conforme, computed, size = catalog_mod.verify_dup("https://x/dup.exe", md5)
    assert conforme is True
    assert computed == md5
    assert size == len(payload)


def test_verify_dup_non_conforme(monkeypatch):
    monkeypatch.setattr(catalog_mod.requests, "get", lambda *a, **k: _FakeResp([b"altered"]))
    conforme, computed, _ = catalog_mod.verify_dup("https://x/dup.exe", "00" * 16)
    assert conforme is False
    assert computed != "00" * 16


def test_verify_dup_requires_expected_hash():
    with pytest.raises(catalog_mod.CatalogError):
        catalog_mod.verify_dup("https://x/dup.exe", "")


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
