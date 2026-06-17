# h4wk3y3 — Pipeline & Modules

Document détaillé sur l'architecture de scan et les **17 modules** qui
composent h4wk3y3.

---

## 🎯 Vue d'ensemble

h4wk3y3 est structuré en **2 catégories** de modules :

| Catégorie | Modules | Lancement |
|---|---|---|
| **Pipeline scan** (par cible) | m01 → m14 (14 modules) | Auto, à chaque `h4wk3y3.py -t <domaine>` |
| **Standalone CVE intelligence** (transverse) | m15, m17, m18 (3 modules) | Manuel via CLI ou bouton UI |

Le pipeline scan **analyse 1 organisme** à la fois (depuis son apex
racine). Les modules CVE intelligence **opèrent sur l'ensemble du
catalogue** (catalogue mondial de vulnérabilités vs inventaire interne).

---

## 🔁 Architecture du pipeline scan

### Orchestration des étapes

```
┌─────────────────────────────────────────────────────────────────┐
│                  PIPELINE 14 MODULES                            │
└─────────────────────────────────────────────────────────────────┘

   ┌─── PRÉ-STAGE ────────────────────────────────────┐
   │  m02  Subdomain Enumeration                       │
   │       (passif: subfinder + crt.sh + chaos…)       │
   └────────────┬─────────────────────────────────────┘
                │ liste de sous-domaines
                ▼
   ┌─── STAGE 1 ──────────────────────────────────────┐
   │  m03  HTTP Validator & Tech Detection             │
   │       (probe HTTP/HTTPS, fingerprint stack)       │
   │       ⚠ bloquant — les modules suivants en       │
   │         dépendent (live_hosts)                    │
   └────────────┬─────────────────────────────────────┘
                │ live_hosts + technologies
                ▼
   ┌─── STAGE 2 — exécution PARALLÈLE ────────────────┐
   │  m04  URL Collector       (gau / waybackurls)    │
   │  m05  Screenshot          (Playwright headless)  │
   │  m06  Subdomain Takeover  (CNAME analysis)       │
   │  m07  Ports & Services    (rustscan + nmap)      │
   │  m08  TLS Audit           (sslyze + custom)      │
   │  m09  Quick Checks        (security headers etc) │
   └────────────┬─────────────────────────────────────┘
                │ URLs collectées
                ▼
   ┌─── STAGE 3 ──────────────────────────────────────┐
   │  m10  Fast Full Fetcher                          │
   │       (bodies de toutes les URLs en masse)       │
   └────────────┬─────────────────────────────────────┘
                │ bodies + headers
                ▼
   ┌─── STAGE 4 ──────────────────────────────────────┐
   │  m11  JavaScript Analyzer                         │
   │       (parse bundles JS, endpoints cachés,        │
   │        secrets hardcodés)                         │
   └────────────┬─────────────────────────────────────┘
                ▼
   ┌─── STAGE 5 — exécution PARALLÈLE ────────────────┐
   │  m12  Pattern Analysis   (grep sur URLs+headers) │
   │  m13  Nuclei Scanner     (templates ciblés tech) │
   └────────────┬─────────────────────────────────────┘
                ▼
   ┌─── STAGE 6 ──────────────────────────────────────┐
   │  m14  Active Validation                          │
   │       (tests actifs ciblés sur signaux trouvés)  │
   └────────────┬─────────────────────────────────────┘
                ▼
   ┌─── POST-SCAN HOOK ────────────────────────────────┐
   │  Attribution automatique (Étape 0003)             │
   │  → marque chaque asset avec son organisme         │
   └───────────────────────────────────────────────────┘

   ┌─── m01 — exécution PRÉLIMINAIRE (avant tout) ────┐
   │  m01  OSINT                                       │
   │       (passive intel : whois, threat intel,      │
   │        Shodan, dorks GitHub)                     │
   └───────────────────────────────────────────────────┘
```

### Pourquoi cette orchestration ?

- **m03 est bloquant** : sans la liste des serveurs vivants, les modules
  suivants n'ont rien à scanner.
- **m04-m09 en parallèle** : ils lisent tous `live_hosts` mais n'écrivent
  pas dans la même table → aucune contention.
- **m10 après m04** : les bodies sont fetchés depuis la liste d'URLs
  collectées par m04 (pas seulement les hosts).
- **m12/m13 en parallèle** : m12 fait du grep local (CPU), m13 fait des
  appels réseau (I/O) → complémentaires.
- **m14 en dernier** : la validation active dépend des signaux levés
  par les modules précédents.

---

## 📦 Détail des 14 modules pipeline

### 🔍 m01 — OSINT

| Aspect | Valeur |
|---|---|
| **Rôle** | Renseignement open-source préliminaire |
| **Inputs** | Apex (ex: `mef.gouv.bj`) |
| **Outputs** | `findings` (info disclosures, secrets exposés, repos GitHub) |
| **Outils** | whois, theHarvester, GitHub dorks, leak databases |
| **Durée** | 1–3 min |

**Détecte** : domaines associés, e-mails exposés, repos GitHub liés à
l'organisme, secrets hardcodés dans le code public, mentions sur leak
databases (HIBP, ScamSearch).

---

### 🌐 m02 — Subdomain Enumeration

| Aspect | Valeur |
|---|---|
| **Rôle** | Cartographier tous les sous-domaines existants |
| **Inputs** | Apex |
| **Outputs** | Table `subdomains` |
| **Outils** | subfinder, assetfinder, crt.sh, chaos, alterx |
| **Durée** | 30 s – 2 min |

**Stratégies** : sources passives (Certificate Transparency, archives DNS,
threat intel feeds) + génération par permutation des sous-domaines déjà
connus.

---

### 🛰 m03 — HTTP Validator & Tech Detection

| Aspect | Valeur |
|---|---|
| **Rôle** | Identifier les serveurs vivants et leur technologie |
| **Inputs** | `subdomains` |
| **Outputs** | Table `live_hosts` (URL, status code, technologies) |
| **Outils** | aiohttp async, 70+ patterns custom, intégration WAF detection |
| **Durée** | 1–3 min selon le nombre de subs |

**Méthode** : probe HTTP/HTTPS sur chaque sous-domaine, parse les
headers, le body, le HTML metadata, le CNAME. Identifie la stack (Apache,
nginx, Laravel, WordPress, IIS, etc.). Détecte la présence d'un WAF
(Cloudflare, Akamai, AWS WAF).

⚠ **Bloquant** : les modules suivants attendent que m03 ait écrit
`live_hosts` pour démarrer.

---

### 🔗 m04 — URL Collector

| Aspect | Valeur |
|---|---|
| **Rôle** | Collecter toutes les URLs historiques connues |
| **Inputs** | `live_hosts` |
| **Outputs** | Table `urls` |
| **Outils** | gau (galaxy of URLs), waybackurls (optionnel) |
| **Durée** | 30 s – 2 min |

**Sources** : Wayback Machine, Common Crawl, URLscan.io. Permet de
retrouver des endpoints anciens souvent oubliés et toujours actifs
(angle d'attaque classique).

---

### 📷 m05 — Screenshot Capturer

| Aspect | Valeur |
|---|---|
| **Rôle** | Capture visuelle de chaque serveur vivant |
| **Inputs** | `live_hosts` |
| **Outputs** | Fichiers PNG + thumbnails + metadata |
| **Outils** | Playwright headless Chromium |
| **Durée** | 1–3 min |

**Utilité** : identification rapide d'admin panels, pages d'erreur
révélatrices (stack trace, version logiciel), pages de login par défaut,
contenu suspect.

---

### 🚨 m06 — Subdomain Takeover Detection

| Aspect | Valeur |
|---|---|
| **Rôle** | Détecter les sous-domaines détournables |
| **Inputs** | `subdomains` (CNAME analysis) |
| **Outputs** | `findings` (severity: critical/high) |
| **Outils** | CNAME parsing + nuclei takeover templates |
| **Durée** | 30 s – 1 min |

**Risque détecté** : CNAME pointant vers un service cloud désaffecté
(Heroku, AWS S3, Azure, Cloudfront…) qu'un attaquant peut réclamer →
prise de contrôle du sous-domaine.

---

### 🔌 m07 — Ports & Services Discovery

| Aspect | Valeur |
|---|---|
| **Rôle** | Scanner tous les ports ouverts |
| **Inputs** | IPs résolues des `live_hosts` |
| **Outputs** | `findings` (services exposés, versions) |
| **Outils** | rustscan (full 1-65535 ports) + nmap (service detection) |
| **Durée** | 3–10 min selon nombre d'hôtes |

**Stratégie** : rustscan en mode rapide pour découvrir les ports
ouverts, puis nmap pour identifier le service exact et sa version
(SSH, DB, Redis, MongoDB, etc.).

---

### 🔐 m08 — TLS Audit

| Aspect | Valeur |
|---|---|
| **Rôle** | Audit cryptographique des certificats |
| **Inputs** | `live_hosts` HTTPS |
| **Outputs** | `findings` (certificat expiré, faible chiffrement, etc.) |
| **Outils** | sslyze + checks custom |
| **Durée** | 1–2 min |

**Vérifie** : expiration, SAN cohérence, suites cipher (CBC, RC4
deprecated), TLS 1.0/1.1 actif, protocoles legacy, HSTS, OCSP stapling.

---

### ⚡ m09 — Quick Checks

| Aspect | Valeur |
|---|---|
| **Rôle** | Vérifications rapides bas niveau |
| **Inputs** | `live_hosts` |
| **Outputs** | `findings` (security headers, robots.txt, cookies…) |
| **Outils** | Custom HTTP probes |
| **Durée** | < 1 min |

**Couvre** : headers de sécurité (CSP, HSTS, X-Frame-Options), robots.txt
mal configuré, sitemap.xml, cookies sans Secure/HttpOnly, .well-known
exposés, .env / .git / .DS_Store accessibles publiquement.

---

### 📥 m10 — Fast Full Fetcher

| Aspect | Valeur |
|---|---|
| **Rôle** | Télécharger en masse les bodies de toutes les URLs |
| **Inputs** | URLs de `live_hosts` + m04 |
| **Outputs** | Cache local des bodies + headers |
| **Outils** | aiohttp parallel + style fff/tomnomnom |
| **Durée** | 2–5 min |

**Utilité** : fournit la matière première (HTML + JS + headers complets)
pour les modules d'analyse (m11, m12).

---

### 🧪 m11 — JavaScript Analyzer

| Aspect | Valeur |
|---|---|
| **Rôle** | Analyser les bundles JS pour secrets et endpoints |
| **Inputs** | Bodies JS de m10 |
| **Outputs** | `findings` (endpoints API cachés, tokens, source maps) |
| **Outils** | parsing JS custom + regex patterns |
| **Durée** | 2–4 min |

**Détecte** : endpoints API non documentés référencés dans le JS,
secrets hardcodés (API keys, JWT, AWS keys), source maps `*.js.map`
exposées (code TypeScript original retrouvé), routes admin cachées.

---

### 🔎 m12 — Pattern Analysis

| Aspect | Valeur |
|---|---|
| **Rôle** | Pattern matching sur tout le contenu collecté |
| **Inputs** | URLs + headers + body snippets |
| **Outputs** | `findings` (data exposure, info leak, IDOR signals) |
| **Outils** | grep natif + patterns YAML maintenus |
| **Durée** | 1–2 min |

**Catégories** : exposition données personnelles (emails, IDs, IBAN,
téléphones), routes sensibles (/admin, /debug, /backup), erreurs SQL
révélées, signaux IDOR (IDs incrémentaux dans URLs).

---

### 🎯 m13 — Targeted Nuclei Scanner

| Aspect | Valeur |
|---|---|
| **Rôle** | Scan vulnérabilités par templates ciblés à la tech |
| **Inputs** | `live_hosts` + `technologies` |
| **Outputs** | `findings` (CVE confirmées, misconfigurations) |
| **Outils** | nuclei + 3 988 templates CVE + 1 000+ templates misc |
| **Durée** | 5–15 min selon nombre d'hôtes |

**Stratégie** : h4wk3y3 sélectionne automatiquement les templates pertinents
selon la technologie détectée (ex: si WordPress détecté → uniquement
templates WordPress). Évite le scan massif aveugle.

---

### ⚔️ m14 — Active Validation

| Aspect | Valeur |
|---|---|
| **Rôle** | Tests actifs ciblés sur signaux remontés |
| **Inputs** | Signaux des modules précédents |
| **Outputs** | `findings` (confirmed avec PoC reproductible) |
| **Outils** | dalfox (XSS), sqlmap (SQLi), ffuf (fuzz endpoints) |
| **Durée** | 5–10 min |

**Méthode** : ne s'exécute QUE sur les endpoints/paramètres déjà
identifiés comme suspects par les modules précédents → minimise le bruit
et le risque OPSEC.

---

## 🛡 3 modules standalone — CVE Intelligence (transverse)

Ces modules ne tournent **pas dans le pipeline scan**. Ils opèrent sur
l'ensemble du catalogue et sont déclenchés manuellement (CLI ou bouton
UI).

### 📡 m15 — CVE Feeds Puller

| Aspect | Valeur |
|---|---|
| **Rôle** | Tirer les flux mondiaux de vulnérabilités |
| **Sources** | NVD (API 2.0), CISA KEV, EPSS, nuclei-templates |
| **Output** | Table `cves` (7 869 rows actuellement) |
| **Lancement** | Manuel : `python3 scripts/cve_pull.py` ou bouton « Refresh feeds » |
| **Durée** | 10 s (mode recent) à 4 min (full annual) |

**Modes** :
- **`recent_only`** (défaut) : pull dernières 8 jours seulement (~10 s).
- **`full`** : pull années complètes (2024/2025/2026), ~30 s avec clé
  API NVD, ~4 min sans.

---

### 🔗 m17 — CVE Correlator

| Aspect | Valeur |
|---|---|
| **Rôle** | Croiser le catalogue CVE avec l'inventaire interne |
| **Inputs** | Table `cves` + table `live_hosts` (technologies détectées) |
| **Outputs** | Table `cve_matches` (856 rows actuellement) |
| **Lancement** | Auto après m15 OU bouton « Re-correlate » |
| **Durée** | < 2 s |

**Stratégie en 2 niveaux** :
- **Tier strict** (confidence 0.6) : matche le produit spécifique
  (ex : `vendor=apache product=solr` → exige « solr » dans la tech list)
- **Tier vendor fallback** (confidence 0.4) : si product générique
  (ex : `apache:http_server`) → fallback vendor seul.

**Pourquoi 2 tiers** : sans ce filtre, une CVE Apache Solr matchait
TOUS les serveurs Apache HTTP → 80 % de faux positifs. Le smart matching
réduit le bruit à ~20 %.

---

### ✅ m18 — CVE Validator (nuclei)

| Aspect | Valeur |
|---|---|
| **Rôle** | Confirmer activement une CVE candidate |
| **Inputs** | `cve_matches` d'une CVE + son template nuclei |
| **Outputs** | Update `cve_matches.validation_state = validated` |
| **Lancement** | Manuel : bouton « Validate with nuclei » sur la page CVE |
| **Durée** | 1–5 min selon nombre d'hôtes |

**Pipeline** :
1. Charge le template `http/cves/<year>/CVE-XXXX.yaml`
2. Liste les `cve_matches` internal in-scope
3. Lance `nuclei -t <template> -l <targets.txt>` avec OPSEC (rate-limit,
   exclude `dos,intrusive,fuzz`)
4. Parse les findings → upgrade `confidence: 0.6 → 0.95`, ajoute
   `evidence` (matched_at, extracted results, info)

**Effet** : passe une « candidate » à « validated » avec preuve PoC.
Les non-validées restent en candidate (pas auto-faux-positif).

---

## 🔄 Cycle de vie d'un scan complet

### Exemple concret : `h4wk3y3.py -t adpme.bj`

| Phase | Modules | Durée typique |
|---|---|---|
| Init | (création scan_id) | < 1 s |
| Pré-stage | m02 | 1 min 30 s |
| Stage 1 | m03 | 2 min |
| Stage 2 (parallèle) | m04, m05, m06, m07, m08, m09 | 4 min (le plus lent : m07 ports) |
| Stage 3 | m10 | 3 min |
| Stage 4 | m11 | 2 min |
| Stage 5 (parallèle) | m12, m13 | 8 min (m13 ralentit avec WAF) |
| Stage 6 | m14 | 4 min |
| Post-scan | attribution + finalize | < 5 s |
| **Total** | | **~25 min** |

(m01 OSINT tourne en pré-paralèle, ~2 min hors chemin critique.)

---

## 📊 Choix de design

### Pourquoi des modules séparés vs un script unique ?

| Bénéfice | Détail |
|---|---|
| **Idempotence** | Chaque module peut être re-exécuté seul sans tout casser |
| **Debug ciblé** | Si m13 plante, on relance m13 sans refaire m01-m12 |
| **Parallélisme** | Les modules indépendants tournent en concurrence |
| **Extensibilité** | Ajouter un nouveau module = créer un fichier + l'ajouter aux STAGES |
| **OPSEC tuning** | Chaque module a sa propre config rate-limit / scope |

### Pourquoi PostgreSQL et pas SQLite ?

- Volumes : 3 356 findings actuels, à terme 50 000+ → besoin index, FTS
- Concurrence : plusieurs scans en parallèle → write contention SQLite
- Types riches : JSONB, INET, ARRAY (utiles pour technologies, IPs)
- Migrations versionnées : Alembic (5 migrations livrées)

### Pourquoi un dashboard SPA sans bundler ?

- **Déploiement single-binary** : pas de `npm install` côté production
- **Babel-Standalone runtime** : compile le JSX dans le navigateur
- **Mises à jour live** : éditer `pages-extra.jsx` + reload = effet
  immédiat, pas de rebuild
- **Compromis assumé** : ~2 s overhead premier load, acceptable
  pour outil CSIRT interne

---

## 🛠 Annexe technique

### Stack complet

| Couche | Technologie |
|---|---|
| Backend | Python 3.13 · FastAPI · SQLAlchemy 2 · Alembic · asyncio + aiohttp |
| Base | PostgreSQL 18 |
| Frontend | React 18 (UMD CDN) + Babel runtime · CSS pur (pas de framework) |
| Scan tools | subfinder, httpx, gau, rustscan, nmap, sslyze, nuclei, playwright, dalfox, sqlmap, ffuf |
| Auth | session cookies HMAC + CSRF tokens + audit log |

### Migrations Alembic livrées

| # | Description |
|---|---|
| 0001 | Schéma initial (scans, subdomains, live_hosts, findings, URLs, etc.) |
| 0002 | Multi-organisations (`organisations`, `targets`) |
| 0003 | Attribution `attributed_apex` sur 3 tables |
| 0004 | CVE Intelligence (`cves`, `cve_matches`, `surface_intel`) |
| 0005 | Fix unicity `UNIQUE NULLS NOT DISTINCT` sur cve_matches |
