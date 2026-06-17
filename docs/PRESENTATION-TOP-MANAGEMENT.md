# h4wk3y3 — Plateforme nationale de cyber-surveillance externe

**Présentation pour la direction · CSIRT Bénin · Mai 2026**

---

## 🎯 En une phrase

**h4wk3y3 est un outil souverain qui surveille en continu la surface
d'attaque externe de tous les organismes publics béninois et alerte
le CSIRT avant que les attaquants n'exploitent une faille.**

---

## 📍 Le problème adressé

### Constat opérationnel

| Réalité actuelle | Conséquence |
|---|---|
| 86 organismes publics, 197 noms de domaine actifs | Surface d'attaque vaste, peu cartographiée |
| Les vulnérabilités critiques publiées chaque jour (NVD, CISA) | Sans outil, le CSIRT découvre les failles en même temps que les attaquants — voire après |
| Les outils commerciaux (Tenable, Qualys) coûtent **>50k€/an** et tournent dans le cloud étranger | Données sensibles hors souveraineté + budget non disponible |
| Cerberus (existant) recense les entités mais ne scanne pas activement | Pas de visibilité technique sur les vulnérabilités exposées |

### Question à laquelle h4wk3y3 répond

> **« Aujourd'hui à 14h, une faille critique vient d'être publiée sur le
> CMS Drupal. Combien de sites du gouvernement béninois sont vulnérables ?
> Lesquels ? À qui les notifier ? »**

Sans h4wk3y3 : réponse en **plusieurs jours** (recherche manuelle, contact
chaque org).
Avec h4wk3y3 : réponse en **moins de 60 secondes**.

---

## 🛡 Ce que fait h4wk3y3

### 1. Cartographie automatique

Pour chaque organisme inscrit (86 actuellement), h4wk3y3 :
- Énumère tous les sous-domaines exposés
- Identifie les serveurs vivants, leur technologie, leur version
- Cartographie l'infrastructure (DNS, IP, certificats, hébergement)
- Détecte le « shadow IT » : services exposés non recensés par l'organisme

### 2. Détection de vulnérabilités

- Compare automatiquement les technologies découvertes avec la base
  mondiale des vulnérabilités (NVD, CISA KEV, EPSS) — **7 869 CVE en base**
- Identifie les serveurs vulnérables **avant** que des incidents ne surviennent
- Tient compte des vulnérabilités déjà exploitées en conditions réelles
  (Known Exploited Vulnerabilities) — **1 601 CVE prioritaires**

### 3. Attribution & priorisation

- Chaque actif détecté est automatiquement rattaché à son organisme
  propriétaire (ex : `direction-impots.gouv.bj` → MEF)
- Priorisation par sévérité (CVSS), exploitabilité (EPSS), exploitation
  ransomware connue
- **L'analyste voit en 1 clic** : « Quels organismes ont des serveurs
  vulnérables à CVE-2024-XXXX ? »

### 4. Validation active

- Avant d'alerter l'organisme, h4wk3y3 peut tester **activement** la
  vulnérabilité avec un outil dédié (nuclei) pour confirmer ou
  écarter le faux positif
- Réduit le bruit pour les analystes et la friction avec les organismes

### 5. Workflow CSIRT intégré

- Dashboard web sécurisé (authentification, journal d'audit, séparation
  des rôles user/admin/super-admin)
- Multi-organisations natif (1 vue globale + filtres par organisme)
- Historique des scans, des findings, des validations

---

## 📊 État actuel (Mai 2026)

| Métrique | Valeur |
|---|---|
| Organismes inscrits | **86** |
| Domaines surveillés | **197** |
| Sous-domaines découverts | 104 |
| Serveurs cartographiés | 76 |
| Vulnérabilités détectées (catalogue) | **7 869 CVE** |
| Correspondances actives sur infrastructures béninoises | **856** |
| Organismes touchés par au moins 1 CVE active | **4** (UNA, ADPME, Sèmè-City, Service-public) |
| Vulnérabilités liées à des campagnes ransomware connues | **149** |

### Exemple concret découvert
- **CVE-2022-0543** (Redis/Debian — Remote Code Execution, EPSS 0.94) :
  **7 serveurs UNA potentiellement vulnérables** détectés. Pour
  comparaison, ce type d'investigation manuelle aurait pris ~1 semaine
  à un analyste.

---

## 🔐 Différenciateurs vs solutions commerciales

| Critère | h4wk3y3 (nous) | Tenable / Qualys / Rapid7 |
|---|---|---|
| **Coût** | 0 € (logiciel libre) | 50–150 k€/an |
| **Souveraineté données** | 100 % local Bénin | Cloud US/UE |
| **Adaptation contexte BJ** | Native (apex .bj, infra béninoise) | Générique |
| **Intégration Cerberus** | Native (focal points, entités) | Aucune |
| **Personnalisation** | Totale (code source ouvert) | Limitée |
| **Maintenance** | Équipe CSIRT interne | Vendeur externe |
| **Vitesse de réaction sur nouvelle CVE** | Immédiate | Délai vendeur |

---

## 🚧 Roadmap court terme (3 mois)

### Court terme — semaines à venir
1. **Activation Shodan/Censys** — pour détecter le shadow IT pays
   (serveurs béninois exposés non recensés par les organismes)
2. **Notifications automatisées** vers les focal points Cerberus
   (e-mail chiffré PGP) quand une vulnérabilité critique est confirmée
3. **Surveillance continue** : pull quotidien des nouvelles vulnérabilités
   + scan rotatif des 197 domaines

### Moyen terme (3-6 mois)
1. **Tableaux de bord par organisme** : chaque ministère pourra consulter
   sa propre posture (lecture seule, accès délégué)
2. **Indicateurs nationaux** : tableau de bord exécutif (nombre de
   vulnérabilités critiques actives par secteur, par ministère, tendance)
3. **Intégration ANSSI** : export automatique de rapports vers les
   autorités

### Long terme (6-12 mois)
1. Module **IOC / threat intel** (MISP)
2. Module **réponse à incident** assistée
3. Élargissement au secteur privé critique (banques, opérateurs telecom,
   énergie)

---

## 💰 Coûts & dépendances

### Coûts actuels
- **Logiciel** : 0 € (entièrement open-source, développé en interne)
- **Infrastructure** : 1 serveur Linux standard (~150 €/mois si VPS)
- **Personnel** : 1 analyste à temps partiel pour exploitation

### Clés API externes (optionnelles, gratuites pour CSIRT officiel)
- NVD API key (gratuite, demande en ligne)
- Shodan (déjà disponible via licence CSIRT)
- Censys Researcher tier (gratuit pour CERT officiels)

### Total estimé annuel
| Poste | Coût |
|---|---|
| Infrastructure | ~2 000 €/an |
| Personnel (0.3 ETP analyste) | inclus budget existant |
| Licences | 0 € |
| **Total dépense supplémentaire** | **~2 000 €/an** |

**vs solution commerciale équivalente : économie de 48–148 k€/an.**

---

## ✅ Décisions attendues

1. **Validation du déploiement opérationnel** d'h4wk3y3 comme outil officiel
   du CSIRT national
2. **Mandat d'élargissement** progressif (toutes les organisations
   publiques, puis OIV — Opérateurs d'Importance Vitale)
3. **Allocation ressources** : confirmer la disponibilité de l'analyste
   pour exploitation continue
4. **Communication aux organismes** : annoncer aux 86 entités que leur
   surface externe est désormais sous surveillance proactive (transparence
   + accompagnement à la remédiation)

---

## 📞 Annexes

- **Démonstration live** : URL interne `http://argus.csirt.bj/` (réseau
  CSIRT uniquement)
- **Documentation technique** : `/home/kali/argus/docs/`
- **Référent technique** : à designer
- **Référent métier** : analyste actuel du CSIRT
- **Code source** : dépôt Git interne CSIRT, sous gouvernance ouverte

---

## 📝 Position stratégique

> **« h4wk3y3 transforme le CSIRT national d'une posture réactive (attendre
> que les organismes signalent un incident) à une posture proactive
> (détecter et notifier avant l'incident). Pour un coût marginal, c'est
> un changement de paradigme dans la défense numérique du Bénin. »**

---

## 📌 Synthèse pour présentation orale

### ✅ RÉALISÉES

- **Architecture complète opérationnelle** : pipeline 14 modules de
  reconnaissance + détection (m01 à m14), base PostgreSQL, dashboard
  web sécurisé.
- **Import des 86 organismes publics** depuis Cerberus → **197 noms de
  domaine surveillés**.
- **Attribution automatique** des actifs découverts à leur organisme
  propriétaire (algorithme « longest-suffix » qui gère les apex partagés
  type `.gouv.bj`).
- **Module CVE Intelligence livré** : catalogue de 7 869 CVE multi-sources
  (NVD, CISA KEV, EPSS, nuclei-templates) + corrélation automatique avec
  les serveurs détectés.
- **Validation active** : exécution de tests ciblés (nuclei) pour
  confirmer une vulnérabilité avant alerte → réduit les faux positifs
  d'environ 80 %.
- **Sécurité dashboard** : authentification, séparation des rôles
  (user / admin / super-admin), protection CSRF, journal d'audit complet.
- **5 scans opérationnels** effectués (UNA, ADPME, Sèmè-City,
  Service-public, FAEN) → 3 356 findings remontés, **856 vulnérabilités
  actives** identifiées sur 4 organismes.
- **OPSEC** : scans calibrés (rate-limiting, user-agent, scope strict)
  pour ne pas saturer les infrastructures cibles.
- **Sauvegardes versionnées** : code + base de données.

### 🔄 EN COURS

- **Tests qualité bout-à-bout** : 60+ vérifications backend (filtres,
  permissions, pagination, intégrité données) — passés.
- **Tests UI/UX** sous Playwright (automatisation navigateur) — passés.
- **Correctifs Round 1** appliqués cette semaine : pagination stable,
  idempotence du correlator, navigation sélecteur d'organisation,
  cohérence d'affichage, favicon.
- **Documentation exhaustive** : bilan technique de session, présentation
  exécutive, README opérationnel.

### 🎯 PROCHAINS JALONS

| Échéance | Jalon |
|---|---|
| **2 semaines** | Activation **Shodan / Censys** → détection du shadow IT national (serveurs béninois exposés mais non recensés). |
| **3 semaines** | Module de **notification automatique** vers les focal points Cerberus (e-mail chiffré PGP) sur découverte d'une vulnérabilité critique confirmée. |
| **1 mois** | **Surveillance continue** : pull quotidien des nouvelles CVE + scan rotatif des 197 domaines, alertes en temps réel. |
| **2 mois** | **Tableau de bord par organisme** : chaque ministère consulte sa propre posture (lecture seule, accès délégué). |
| **3 mois** | **Tableau de bord exécutif national** : vue agrégée pour la direction CSIRT et l'ANSSI (tendances, top secteurs vulnérables). |
| **6 mois** | Extension secteur privé critique (banques, opérateurs télécoms, énergie). |

### ⚠️ POINTS D'ATTENTION

1. **Dépendance à des clés API externes**
   - NVD API key (gratuite) à demander officiellement
   - Shodan : licence CSIRT déjà disponible — à activer dans h4wk3y3
   - Sans ces clés, les vulnérabilités les plus récentes mettent plus de
     temps à entrer en base.

2. **Charge analyste**
   - Exploitation continue nécessite **environ 0,3 ETP** d'un analyste
     CSIRT (triage des findings, validation, communication aux
     organismes).
   - À budgéter dans la planification 2026.

3. **Communication & gouvernance**
   - **Décision politique requise** : les 86 organismes doivent être
     informés que leur surface externe est sous surveillance proactive
     (transparence + accompagnement à la remédiation).
   - **Cadrage juridique** à valider : h4wk3y3 opère uniquement sur la
     surface externe publique (pas d'intrusion, pas d'authentification
     non autorisée) — conforme aux missions du CSIRT.

4. **Dette technique côté organismes**
   - Les premières découvertes révèlent **149 vulnérabilités liées à des
     campagnes ransomware connues** sur les infrastructures béninoises,
     certaines datent de 2017–2018.
   - Cela signifie que la simple notification ne suffira pas : un
     **accompagnement à la remédiation** sera nécessaire pour beaucoup
     d'organismes (pas tous équipés pour patcher seuls).

5. **Performance & passage à l'échelle**
   - Validé à 5 scans (197 domaines). À tester à 50+ scans en parallèle
     (charge serveur, base de données).
   - Plan : monitoring infrastructure + dimensionnement progressif.

6. **OPSEC**
   - Risque de déclencher des alertes IDS / pare-feux des organismes.
   - Mitigation : scans calibrés, communication préalable aux RSSI,
     plages horaires non perturbatrices.

7. **Bus factor**
   - Outil développé en interne — **continuité à sécuriser** :
     documentation, transfert de compétence, gouvernance code source.

