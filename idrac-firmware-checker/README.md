# Vérificateur d'intégrité firmware — iDRAC Dell

Application web Flask **autonome** qui se connecte à un iDRAC Dell, lit les
firmwares installés, télécharge le **catalogue officiel Dell**, puis affiche
en **temps réel** un tableau comparatif : version installée vs version
officielle, état de conformité (🟢 intègre / 🔴 non conforme) et un bouton
**« Télécharger la mise à jour »** pour chaque firmware obsolète.

## Deux axes distincts : intégrité (sécurité) et mise à jour

L'application sépare volontairement **deux états indépendants** par firmware —
c'est le cœur de sa valeur :

### 1. Intégrité (hash) — axe de sécurité, **primordial**

S'appuie sur l'**attestation SPDM d'iDRAC9** (licence **Datacenter**, firmware
**≥ 6.10** ; couvre les **contrôleurs PERC** et **cartes réseau NIC**). Deux
signaux distincts sont combinés :

- **Authenticité de l'identité** — l'iDRAC vérifie le certificat matériel signé
  Dell du périphérique (détection d'une contrefaçon / d'une altération dans la
  chaîne d'approvisionnement). Un **échec = Compromis**, quelles que soient les
  mesures.
- **Mesures firmware** — à **version égale**, l'empreinte de mesure SPDM est
  comparée à l'empreinte **connue-bonne** de la baseline.

| État | Signification | Couleur |
|------|---------------|---------|
| **Intègre** | identité non invalidée **et** mesure == référence | 🟢 vert |
| **Compromis** | échec d'authenticité **ou** même version mais mesure différente | 🔴 rouge |
| **Non vérifiable** | pas de mesure SPDM et/ou pas de baseline à version égale | ⚪ gris |

Sous le badge, un sous-indicateur montre l'authenticité de l'identité :
✔ *identité* / ✖ *identité* / ◦ *non attesté*.

Un firmware **à jour peut être compromis** (identité falsifiée, ou même version
mais mesure modifiée) : c'est le cas le plus grave, signalé indépendamment de la
version. Le BIOS et l'iDRAC eux-mêmes ne sont pas couverts par SPDM → *non
vérifiable* sur cet axe (comportement honnête, pas de faux « intègre »).

### 2. Mise à jour (version) — axe informatif

| État | Signification |
|------|---------------|
| **À jour** | version installée ≥ dernière version du catalogue |
| **Mise à jour disponible** | version plus récente publiée → bouton de téléchargement |
| **Inconnu** | aucun paquet correspondant au catalogue |

Les deux axes sont calculés séparément et affichés dans deux colonnes ; la
couleur de ligne suit l'axe **intégrité** (sécurité), prioritaire.

## Fonctionnalités

- Saisie IP / identifiant / mot de passe de l'iDRAC.
- Récupération des firmwares installés via **Redfish** (API HTTP) ou **racadm** (CLI).
- **Attestation SPDM iDRAC9** via `/redfish/v1/ComponentIntegrity` : authenticité de
  l'identité (GET) + mesures firmware via l'action `SPDMGetSignedMeasurements` (POST + nonce).
- Comparaison d'intégrité contre une **baseline** d'empreintes connues-bonnes.
- Téléchargement + cache du catalogue Dell (`Catalog.xml.gz`), lu en flux (`iterparse`).
- Tableau comparatif à **deux axes** diffusé **ligne par ligne** (flux NDJSON).
- Bouton de téléchargement du paquet officiel pour les mises à jour disponibles.
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
| `IDRAC_BASELINE`       | Chemin de la baseline d'empreintes connues-bonnes           | *(vide → intégrité « non vérifiable »)*            |

Démo hors-ligne avec le catalogue et la baseline d'exemple fournis :

```bash
IDRAC_LOCAL_CATALOG="$PWD/sample_catalog.xml" \
IDRAC_BASELINE="$PWD/sample_baseline.json" \
python app.py
```

## D'où viennent les empreintes (iDRAC9 SPDM)

Il faut distinguer trois empreintes, souvent confondues :

| Empreinte | Source | Rôle |
|-----------|--------|------|
| **Mesure SPDM** du firmware en exécution | Action `SPDMGetSignedMeasurements` sur `ComponentIntegrity` | ce qui tourne réellement (PERC/NIC) |
| **Empreinte de référence** connue-bonne | **Baseline** (`sample_baseline.json`) capturée sur un hôte de confiance | l'attendu à version égale |
| `hashMD5` du **paquet** DUP | `Catalog.xml` de Dell | vérifie un *téléchargement*, **pas** l'exécution |

La vérification d'intégrité compare la **mesure SPDM** à l'**empreinte de
référence** de la baseline, **à version identique** — plus le signal
d'**authenticité** de l'identité (GET). Le `hashMD5` du catalogue ne sert **pas**
à cette comparaison (c'est le hash d'un fichier d'installation, pas du firmware
en place) ; il est seulement rattaché au bouton de téléchargement.

Si l'iDRAC n'expose pas d'attestation SPDM (licence/firmware/périphérique non
couvert), ou si aucune baseline n'est fournie pour la version installée,
l'intégrité est honnêtement affichée comme **Non vérifiable** plutôt que
faussement « intègre ».

### Comment la mesure est dérivée

`SPDMGetSignedMeasurements` renvoie `SignedMeasurements` (base64) = les blocs de
mesure **+ une signature** dépendant du nonce (donc variable à chaque appel).
`spdm.py` extrait les **blocs de mesure** (format DMTF DSP0274,
`[Index|Spec|Size|Value]`), écarte la signature, et en dérive une empreinte
SHA-256 stable.

> ⚠️ Le décodage binaire DSP0274 suit la spécification mais n'a pas été validé
> contre une unité iDRAC9 réelle. Il est **tolérant** et surtout
> **auto-cohérent** : la baseline étant capturée avec le *même* extracteur,
> toute divergence de mesure est détectée même si le décodage absolu diffère.
> Un échantillon réel de réponse permet de figer le parseur exactement.

### Établir une baseline

Capturez les mesures SPDM d'un hôte de confiance (fraîchement flashé depuis les
paquets Dell officiels) et enregistrez-les au format de `sample_baseline.json` :
liste d'objets `{name, version, hash, algorithm}`. Réutilisez ensuite ce fichier
pour détecter toute divergence sur les autres hôtes ou dans le temps.

## Architecture

| Fichier            | Rôle                                                             |
|--------------------|------------------------------------------------------------------|
| `app.py`           | Serveur Flask, endpoint `/api/scan` (flux NDJSON temps réel).    |
| `idrac_client.py`  | Connexion iDRAC (Redfish + repli racadm), inventaire, appels d'attestation.|
| `spdm.py`          | Attestation SPDM iDRAC9 : authenticité + extraction des mesures (DSP0274).|
| `catalog.py`       | Téléchargement, décompression, parsing en flux du catalogue Dell.|
| `baseline.py`      | Chargement/interrogation de la baseline d'empreintes connues-bonnes.|
| `compare.py`       | Calcul des **deux axes** (intégrité hash + mise à jour version).  |
| `matching.py`      | Helpers de correspondance de noms et de comparaison de versions. |
| `templates/`, `static/` | Interface web (formulaire + tableau deux axes temps réel). |
| `sample_catalog.xml`, `sample_baseline.json` | Données d'exemple pour la démo/les tests. |
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
