"""Application Flask : vérificateur d'intégrité des firmwares iDRAC Dell.

Flux :

1. L'utilisateur saisit IP / identifiant / mot de passe de l'iDRAC.
2. Le serveur se connecte via Redfish (ou racadm) et lit les firmwares
   installés.
3. Le catalogue officiel Dell est téléchargé (et mis en cache) ; ses versions
   et hash de référence sont extraits.
4. Les résultats sont diffusés **en temps réel** (flux NDJSON) : chaque ligne
   comparative apparaît dès qu'elle est calculée, avec un indicateur
   vert (intègre) / rouge (non conforme) et un bouton de mise à jour.

Sécurité : les identifiants ne sont jamais stockés ni journalisés ; ils ne
servent qu'à la requête en cours.
"""

from __future__ import annotations

import json
import os
from typing import Iterator

from flask import Flask, Response, render_template, request, stream_with_context

from catalog import CatalogError, load_catalog
from compare import build_row
from compare import CatalogIndex
from idrac_client import IdracClient, IdracError

app = Flask(__name__)

# Emplacement du cache catalogue (24 h par défaut).
CACHE_DIR = os.environ.get("IDRAC_CACHE_DIR", os.path.join(os.path.dirname(__file__), ".cache"))
CATALOG_CACHE = os.path.join(CACHE_DIR, "Catalog.xml")
# Catalogue local optionnel (utile hors-ligne / démo).
LOCAL_CATALOG = os.environ.get("IDRAC_LOCAL_CATALOG")
CATALOG_URL = os.environ.get("IDRAC_CATALOG_URL", "https://downloads.dell.com/catalog/Catalog.xml.gz")


def _sse_free_line(obj: dict) -> str:
    """Sérialise un événement en NDJSON (une ligne JSON + saut de ligne)."""
    return json.dumps(obj, ensure_ascii=False) + "\n"


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan() -> Response:
    payload = request.get_json(silent=True) or request.form
    host = (payload.get("ip") or "").strip()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    verify_ssl = str(payload.get("verify_ssl", "")).lower() in ("1", "true", "on", "yes")
    transport = (payload.get("transport") or "redfish").strip()

    def generate() -> Iterator[str]:
        if not host or not username:
            yield _sse_free_line({"type": "error", "message": "IP et identifiant sont requis."})
            return

        # 1) Inventaire des firmwares installés.
        yield _sse_free_line({"type": "status", "step": "connect", "message": f"Connexion à {host}…"})
        client = IdracClient(host, username, password, verify_ssl=verify_ssl)
        try:
            installed = client.get_firmware_inventory(transport=transport)
        except IdracError as exc:
            yield _sse_free_line({"type": "error", "message": str(exc)})
            return
        yield _sse_free_line(
            {"type": "status", "step": "inventory", "message": f"{len(installed)} firmware(s) installé(s) détecté(s)."}
        )

        # 2) Catalogue officiel Dell.
        yield _sse_free_line(
            {"type": "status", "step": "catalog", "message": "Téléchargement du catalogue Dell…"}
        )
        try:
            catalog = load_catalog(
                url=CATALOG_URL,
                cache_path=CATALOG_CACHE,
                local_path=LOCAL_CATALOG,
            )
        except CatalogError as exc:
            yield _sse_free_line({"type": "error", "message": f"Catalogue : {exc}"})
            return
        yield _sse_free_line(
            {"type": "status", "step": "catalog_ok", "message": f"Catalogue chargé ({len(catalog)} paquets)."}
        )

        # 3) Comparaison, diffusée ligne par ligne (temps réel).
        index = CatalogIndex(catalog)
        yield _sse_free_line({"type": "status", "step": "compare", "message": "Comparaison en cours…"})
        for entry in installed:
            official = index.latest_for(entry.name, entry.component_type)
            row = build_row(entry.name, entry.component_type, entry.version, official)
            yield _sse_free_line({"type": "row", "row": row.to_dict()})

        yield _sse_free_line({"type": "done", "message": "Analyse terminée."})

    return Response(stream_with_context(generate()), mimetype="application/x-ndjson")


@app.route("/healthz")
def healthz() -> Response:
    return Response("ok", mimetype="text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
