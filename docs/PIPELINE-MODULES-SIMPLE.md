# h4wk3y3 — Modules

## Pipeline scan (par cible)

**m01 — OSINT**
Renseignement open-source préliminaire sur l'organisme.
Outils : whois, theHarvester, GitHub dorks, leak databases (HIBP).
Dépendance : aucune.

**m02 — Subdomain Enumeration**
Énumération passive des sous-domaines.
Outils : subfinder, assetfinder, crt.sh, chaos, alterx, puredns.
Dépendance : aucune.

**m03 — HTTP Validator & Tech Detection**
Identifie les serveurs vivants et leur stack technologique.
Outils : aiohttp, httpx, 70+ patterns custom.
Dépendance : m02 (liste sous-domaines).

**m04 — URL Collector**
Récupère les URLs historiques connues.
Outils : gau, waybackurls.
Dépendance : m03 (live_hosts).

**m05 — Screenshot Capturer**
Capture visuelle de chaque serveur vivant.
Outils : Playwright headless Chromium.
Dépendance : m03.

**m06 — Subdomain Takeover Detection**
Détecte les sous-domaines détournables (CNAME vers cloud désaffecté).
Outils : nuclei (templates takeover) + CNAME parsing.
Dépendance : m02, m03.

**m07 — Ports & Services Discovery**
Scan des ports ouverts + identification services.
Outils : rustscan (1-65535) + nmap.
Dépendance : m03 (IPs résolues).

**m08 — TLS Audit**
Audit cryptographique des certificats.
Outils : sslyze + checks custom.
Dépendance : m03 (live_hosts HTTPS).

**m09 — Quick Checks**
Vérifications rapides (security headers, .env, .git, robots.txt…).
Outils : probes HTTP custom.
Dépendance : m03.

**m10 — Fast Full Fetcher**
Téléchargement en masse des bodies (style fff/tomnomnom).
Outils : aiohttp parallel.
Dépendance : m04 (URLs).

**m11 — JavaScript Analyzer**
Parse les bundles JS : endpoints cachés, secrets, source maps.
Outils : regex patterns + parser custom.
Dépendance : m10 (bodies).

**m12 — Pattern Analysis**
Grep natif sur URLs, headers, bodies (data exposure, IDOR signals).
Outils : grep + patterns YAML.
Dépendance : m04, m10.

**m13 — Targeted Nuclei Scanner**
Scan vulnérabilités avec templates ciblés à la stack détectée.
Outils : nuclei + 4000+ templates.
Dépendance : m03 (technologies).

**m14 — Active Validation**
Tests actifs ciblés sur les signaux remontés.
Outils : dalfox (XSS), sqlmap (SQLi), ffuf.
Dépendance : tous les précédents (consomme leurs signaux).

---

## CVE Intelligence (transverse, hors pipeline)

**m15 — CVE Feeds Puller**
Tire les flux mondiaux de vulnérabilités vers la base.
Outils / sources : NVD API 2.0, CISA KEV, EPSS, nuclei-templates.
Dépendance : aucune.
Lancement : manuel (CLI ou bouton « Refresh feeds »).

**m17 — CVE Correlator**
Croise le catalogue CVE avec l'inventaire interne (live_hosts).
Outils : SQL + tokenisation custom.
Dépendance : m15 (catalogue) + m03 (live_hosts).
Lancement : auto après m15 ou bouton « Re-correlate ».

**m18 — CVE Validator**
Confirme activement une CVE candidate par test ciblé.
Outils : nuclei (template spécifique à la CVE).
Dépendance : m17 (cve_matches) + template existant pour la CVE.
Lancement : manuel (bouton « Validate with nuclei »).
