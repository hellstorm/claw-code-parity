# Vérificateur d'intégrité firmware — iDRAC Dell

Application web Flask **autonome** qui se connecte à un iDRAC Dell, lit les
firmwares installés, télécharge le **catalogue officiel Dell**, puis affiche
en **temps réel** un tableau comparatif : version installée vs version
officielle, état de conformité (🟢 intègre / 🔴 non conforme) et un bouton
**« Télécharger la mise à jour »** pour chaque firmware obsolète.

## Fonctionnalités

- Saisie IP / identifiant / mot de passe de l'iDRAC.
- Récupération des firmwares installés via **Redfish** (API HTTP) ou **racadm** (CLI).
- Téléchargement + cache du catalogue Dell (`Catalog.xml.gz`), lu en flux (`iterparse`).
- Extraction des versions officielles et du **hash MD5 de référence** de chaque paquet.
- Tableau comparatif diffusé **ligne par ligne** (flux NDJSON) avec indicateurs colorés.
- Bouton de téléchargement direct du paquet officiel pour les firmwares non conformes.
- Aucun identifiant stocké ni journalisé.

## Installation

```bash
cd idrac-firmware-checker
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
```

## Configuration (variables d'environnement)

| Variable               | Rôle                                                        | Défaut                                             |
|------------------------|-------------------------------------------------------------|----------------------------------------------------|
| `PORT`                 | Port d'écoute                                                | `5000`                                             |
| `IDRAC_CATALOG_URL`    | URL du catalogue Dell                                       | `https://downloads.dell.com/catalog/Catalog.xml.gz`|
| `IDRAC_CACHE_DIR`      | Dossier de cache du catalogue                              | `./.cache`                                          |
| `IDRAC_LOCAL_CATALOG`  | Chemin d'un catalogue local (mode hors-ligne / démo)        | *(vide)*                                           |

Démo hors-ligne avec le catalogue d'exemple fourni :

```bash
IDRAC_LOCAL_CATALOG="$PWD/sample_catalog.xml" python app.py
```

## Note importante sur la « vérification par hash »

Le catalogue Dell fournit un `hashMD5` **par paquet de mise à jour (DUP)**,
c'est-à-dire le hash du *fichier téléchargeable*, **pas** du firmware en cours
d'exécution sur le serveur. Ni Redfish ni racadm n'exposent de hash du firmware
installé.

Par conséquent :

- Le hash affiché dans le tableau est le **hash de référence du paquet officiel**
  (utile pour vérifier un téléchargement, pas l'exécution en place).
- L'état **intègre / non conforme** est déterminé par **comparaison de version**
  avec la dernière version officielle du catalogue — le seul signal réellement
  exploitable côté iDRAC.

C'est un choix assumé et documenté : l'application ne simule pas une
vérification de hash du firmware installé qui n'existe pas techniquement.

## Architecture

| Fichier            | Rôle                                                             |
|--------------------|------------------------------------------------------------------|
| `app.py`           | Serveur Flask, endpoint `/api/scan` (flux NDJSON temps réel).    |
| `idrac_client.py`  | Connexion iDRAC (Redfish + repli racadm), inventaire firmware.   |
| `catalog.py`       | Téléchargement, décompression, parsing en flux du catalogue Dell.|
| `compare.py`       | Rapprochement firmware↔catalogue et calcul du statut d'intégrité.|
| `templates/`, `static/` | Interface web (formulaire + tableau temps réel).           |
| `sample_catalog.xml` | Catalogue d'exemple pour la démo/les tests hors-ligne.         |
| `tests/`           | Tests unitaires (`pytest`), sans accès réseau.                   |

## Tests

```bash
. .venv/bin/activate
pip install pytest
python -m pytest tests/ -q
```

## Sécurité et usage

Outil de **contrôle de conformité défensif** destiné aux administrateurs
disposant d'un accès légitime à leurs iDRAC. Les identifiants transitent
uniquement pour la requête en cours. Le serveur écoute par défaut sur
`127.0.0.1` ; exposez-le derrière un reverse-proxy TLS avant tout usage réseau.
La vérification TLS de l'iDRAC est désactivable (certificats auto-signés
fréquents) mais réactivable via la case dédiée.
