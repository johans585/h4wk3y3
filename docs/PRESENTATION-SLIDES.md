---
marp: true
theme: default
paginate: true
backgroundColor: #0e1117
color: #e8eaed
header: '**h4wk3y3** · CSIRT Bénin · Mai 2026'
footer: 'Confidentiel — Direction CSIRT'
style: |
  section {
    font-family: 'Helvetica', sans-serif;
    padding: 60px 80px;
  }
  h1 {
    color: #59bcff;
    border-bottom: 2px solid #59bcff;
    padding-bottom: 12px;
  }
  h2 {
    color: #5be7a9;
  }
  strong { color: #ffcd5a; }
  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.85em;
  }
  th { background: #1e2329; color: #59bcff; padding: 8px; }
  td { padding: 6px 8px; border-bottom: 1px solid #2c3138; }
  .highlight {
    background: linear-gradient(135deg, #ff5e62 0%, #ffcd5a 100%);
    color: #0e1117;
    padding: 4px 12px;
    border-radius: 4px;
    font-weight: bold;
  }
  blockquote {
    border-left: 4px solid #59bcff;
    padding-left: 20px;
    color: #a3a8b3;
    font-style: italic;
  }
---

<!-- _class: lead -->

# **ARGUS**

## Plateforme nationale de cyber-surveillance externe

Un outil souverain qui surveille en continu la surface d'attaque des
organismes publics béninois et alerte le CSIRT **avant** les attaquants.

<br>

**CSIRT Bénin · Direction · Mai 2026**

---

# 🎯 Le problème

> **« Une faille critique sur Drupal vient d'être publiée à 14h.
> Combien de sites du gouvernement béninois sont vulnérables ?
> Lesquels ? À qui les notifier ? »**

<br>

| Sans h4wk3y3 | Avec h4wk3y3 |
|---|---|
| Réponse en **plusieurs jours** | Réponse en **< 60 secondes** |
| Recherche manuelle, mail-à-mail | Liste exhaustive automatique |
| Découverte = en même temps que l'attaquant | Détection **avant l'incident** |

---

# 🛡 Ce que fait h4wk3y3

1. **Cartographie automatique** — sous-domaines, serveurs, technologies, certificats
2. **Détection vulnérabilités** — corrélation avec 7 869 CVE mondiales (NVD, KEV, EPSS)
3. **Attribution automatique** — chaque actif rattaché à son organisme
4. **Validation active** — confirme une faille par test ciblé avant alerte
5. **Workflow CSIRT intégré** — dashboard sécurisé, audit, rôles, multi-organisations

---

# 📊 État actuel — Mai 2026

| Métrique | Valeur |
|---|---|
| Organismes inscrits | **86** |
| Domaines surveillés | **197** |
| Serveurs cartographiés | 76 |
| Catalogue CVE en base | **7 869** |
| Vulnérabilités actives sur infra béninoise | **856** |
| Liées à campagnes ransomware connues | **149** |
| Organismes touchés (échantillon) | 4 |

---

# 💥 Exemple concret

## **CVE-2022-0543** — Redis Lua Sandbox Escape (RCE)

- **EPSS 0,94** → probabilité quasi-certaine d'exploitation
- **KEV** (CISA Known Exploited) — déjà exploitée dans la nature
- Détection h4wk3y3 : **7 serveurs UNA potentiellement vulnérables**

<br>

> ⏱ **Temps d'investigation manuelle estimée : 1 semaine**
> **Temps h4wk3y3 : ~30 secondes**

---

# 🔐 Vs solutions commerciales

| Critère | h4wk3y3 | Tenable / Qualys |
|---|---|---|
| Coût | **0 €** | 50–150 k€/an |
| Souveraineté données | **100 % local** | Cloud US/UE |
| Adaptation contexte BJ | **Native** | Générique |
| Intégration Cerberus | **Native** | Aucune |
| Personnalisation | **Totale** (code ouvert) | Limitée |
| Vitesse d'adaptation | **Immédiate** | Délai vendeur |

<br>

**Économie : 48–148 k€/an vs équivalent commercial.**

---

# ✅ RÉALISÉES

- Architecture complète **opérationnelle** (14 modules)
- Import **86 organismes / 197 domaines** depuis Cerberus
- Attribution automatique apex → organisme (apex partagés `.gouv.bj` gérés)
- **Module CVE Intelligence** livré (catalogue + corrélation + validation)
- Dashboard sécurisé : auth, rôles, CSRF, audit
- **5 scans opérationnels** : 3 356 findings, 856 vulnérabilités actives
- OPSEC calibré (rate-limit, scope strict)
- Sauvegardes versionnées (code + base)

---

# 🔄 EN COURS

- **Tests qualité bout-à-bout** : 60+ vérifications backend passées
- **Tests UI/UX automatisés** (Playwright) passés
- **Round 1 de correctifs** appliqué : pagination, idempotence, navigation, cohérence
- **Documentation exhaustive** : bilan technique + présentation exécutive
- Préparation activation **Shodan / Censys**

---

# 🎯 PROCHAINS JALONS

| Échéance | Jalon |
|---|---|
| 2 sem. | **Shodan / Censys** → détection shadow IT national |
| 3 sem. | **Notifications automatiques PGP** vers focal points Cerberus |
| 1 mois | **Surveillance continue** : pull CVE quotidien + scan rotatif |
| 2 mois | **Dashboard par organisme** (vue déléguée) |
| 3 mois | **Tableau de bord exécutif national** (direction + ANSSI) |
| 6 mois | Extension **secteur privé critique** (banques, télécoms, énergie) |

---

# ⚠️ POINTS D'ATTENTION

1. **Clés API externes** — NVD à demander, Shodan à activer
2. **Charge analyste** — 0,3 ETP pour exploitation continue (à budgéter 2026)
3. **Décision politique** — informer officiellement les 86 organismes
4. **Dette technique organismes** — CVE 2017-2018 toujours actives → **accompagnement remédiation** nécessaire
5. **Passage à l'échelle** — validé à 5 scans, à éprouver à 50+
6. **OPSEC** — risque alertes IDS → communication préalable RSSI
7. **Bus factor** — outil interne, **continuité à sécuriser**

---

# ✅ Décisions attendues

<br>

1. **Validation** du déploiement opérationnel d'h4wk3y3 comme outil officiel du CSIRT national

2. **Mandat d'élargissement** progressif (toutes les organisations publiques, puis OIV)

3. **Allocation ressources** : confirmer 0,3 ETP analyste exploitation continue

4. **Communication aux organismes** : annoncer la surveillance proactive + accompagnement remédiation

---

<!-- _class: lead -->

# Conclusion

> **« h4wk3y3 transforme le CSIRT national d'une posture réactive
> à une posture proactive.**
>
> **Pour un coût marginal, c'est un changement de paradigme
> dans la défense numérique du Bénin. »**

<br>

## Merci · Questions ?

