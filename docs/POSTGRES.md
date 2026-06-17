# h4wk3y3 on Postgres — setup & operations

> **h4wk3y3 est Postgres-only depuis 2026-05.** SQLite a été retiré
> intégralement (code, deps, tests, docs). La seule DB supportée est
> Postgres ≥ 14.

---

## Architecture du stockage (hybride raisonné)

| Donnée | Stockage | Pourquoi |
|---|---|---|
| **findings, subdomains, live_hosts, scans, users, audit_log, dashboard_runs** | **Postgres** (source unique) | Structuré, queryable, dédupable, requis pour le diff inter-scans, multi-org, asset graph (Phase 2) |
| **screenshots PNG, bodies HTML, JS files** | `output/<domain>/` | Blobs lourds, write-once, jamais filtrés/agrégés en SQL |
| **patterns.json, gf_*.txt, fetch_results.json, active_findings.json, js_secrets.json, js_endpoints.json, email_security.json, api_specs.json, takeovers.json, secrets_validated.json, dns_records.json, cnames.json, ips.json, ptrs.json** | `output/<domain>/` | Audit trail des modules + enrichissement non encore en DB |
| **findings.json, findings_solid.json, findings_candidates.json, diff_new.json, diff_gone.json, scan_summary.json** | `output/<domain>/` | **Export généré** — projection de la DB pour `jq`/git/portabilité. Toggle via `general.export_json_artefacts: false` |

**Règle générale** : 
- Données *structurées et queryables cross-domain/cross-org* → DB
- *Blobs* (binaires, HTML chunks, JS files) → fichiers
- *Audit trail* spécifique aux modules → fichiers (peut migrer en DB plus tard si besoin)

**Une seule source par type** : pas de double-écriture qui peut désynchroniser.

### Re-seed PG depuis des fichiers JSON existants

Après un wipe DB (ou si tu installes h4wk3y3 sur une nouvelle machine et veux
récupérer des scans antérieurs depuis le dossier `output/`) :

```bash
# Dry-run
argus-env/bin/python scripts/reseed_pg_from_output.py

# Apply
argus-env/bin/python scripts/reseed_pg_from_output.py --apply

# Un seul domaine
argus-env/bin/python scripts/reseed_pg_from_output.py --domain anpe.bj --apply
```

Le script lit `output/<domain>/{scan_summary.json, findings.json,
live_hosts.json, subdomains.txt}` et insère en DB. Idempotent : la dedup
par fingerprint évite les doublons sur re-runs.

---

## Setup 5-min

### 1. Installer Postgres

```bash
# Debian/Kali
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql

# macOS
brew install postgresql@15
brew services start postgresql@15
```

### 2. Créer user + DB

```bash
sudo -u postgres psql <<'SQL'
ALTER DATABASE template1 REFRESH COLLATION VERSION;   -- fix Kali glibc upgrade
CREATE USER argus WITH PASSWORD 'change-me-now';
CREATE DATABASE argus_main OWNER argus;
GRANT ALL PRIVILEGES ON DATABASE argus_main TO argus;
SQL
```

Vérifie :

```bash
PGPASSWORD=change-me-now psql -h 127.0.0.1 -U argus -d argus_main -c "SELECT version();"
```

### 3. Configurer h4wk3y3

Édite `config/h4wk3y3.yaml` :

```yaml
general:
  output_dir: "./output"
  db_url: "postgresql+psycopg://argus:change-me-now@127.0.0.1/argus_main"
  log_level: "INFO"
```

Override possible via `ARGUS_DB_URL=...` (utile pour CI / staging sans
toucher au YAML).

### 4. Créer le schéma

```bash
cd /home/kali/argus
argus-env/bin/alembic upgrade head
```

Vérifie :

```bash
PGPASSWORD=change-me-now psql -h 127.0.0.1 -U argus -d argus_main -c "\dt"
```

Tu dois voir 8 tables : `alembic_version`, `audit_log`, `dashboard_runs`,
`findings`, `live_hosts`, `scans`, `subdomains`, `users`.

---

## Tests

Les tests h4wk3y3 tournent sur **la même DB Postgres** que la prod
(`general.db_url` ou `ARGUS_TEST_POSTGRES_URL`). Le `conftest.py`
TRUNCATE les 7 tables h4wk3y3 entre chaque test pour garantir un état
propre.

```bash
# Tests par défaut (utilise h4wk3y3.yaml general.db_url)
argus-env/bin/python -m pytest tests/

# CI / staging : override le DSN
ARGUS_TEST_POSTGRES_URL="postgresql+psycopg://argus:pw@localhost/argus_test" \
  argus-env/bin/python -m pytest tests/
```

**Note** : `test_alembic.py` est destructive — il DROP SCHEMA public
puis le recrée pour chaque cas, ce qui invalide brièvement les autres
fixtures. Le fixture restaure les tables via `Base.metadata.create_all`
avant de céder la main au test suivant. Si tu vois des erreurs
"relation does not exist" dans la même session, c'est probablement un
test_alembic qui a leaké entre les cas — le run isolé passe (`pytest
tests/test_alembic.py`).

---

## Schémas / migrations

### Créer une nouvelle migration

```bash
# Modifie core/orm.py (ajout colonne, table, index)
argus-env/bin/alembic revision --autogenerate -m "add organisation table"
# Inspecte alembic/versions/<hash>_add_organisation_table.py
argus-env/bin/alembic upgrade head
```

### Stamp une DB pré-existante

Si quelqu'un a une DB Postgres déjà créée hors Alembic (rare maintenant
que `h4wk3y3.yaml` pointe sur PG par défaut) :

```bash
argus-env/bin/alembic stamp 0001
argus-env/bin/alembic upgrade head
```

### Rollback

```bash
# Revenir 1 migration en arrière
argus-env/bin/alembic downgrade -1
# Revenir à la baseline
argus-env/bin/alembic downgrade 0001
```

---

## Backup / restore

```bash
# Backup
pg_dump -h 127.0.0.1 -U argus -d argus_main -Fc -f argus_$(date +%Y%m%d).dump

# Restore (drop + recreate first)
sudo -u postgres dropdb argus_main
sudo -u postgres createdb argus_main -O argus
pg_restore -h 127.0.0.1 -U argus -d argus_main argus_20260514.dump
```

---

## Performance — paramètres recommandés

Pour un workload single-user / dev, les defaults Postgres suffisent.
Pour un dashboard partagé entre 3-5 users :

```sql
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '16MB';
ALTER SYSTEM SET max_connections = 100;
SELECT pg_reload_conf();
```

Puis benchmarker avec un vrai scan multi-domaines avant d'aller plus loin.

---

## Troubleshooting

### `template database "template1" has a collation version mismatch`

Bug Kali post-upgrade glibc. Fix une fois :

```bash
sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;"
```

### `connection refused on 127.0.0.1:5432`

Service pas démarré :

```bash
sudo systemctl status postgresql
sudo systemctl start postgresql
```

### `password authentication failed`

Vérifie `pg_hba.conf` (souvent `/etc/postgresql/<version>/main/pg_hba.conf`)
— la ligne `host all all 127.0.0.1/32 md5` doit être présente avant
`scram-sha-256` si tu as un client ancien.

### Schema drift Alembic ↔ ORM

```bash
# Compare orm.py vs DB
argus-env/bin/alembic check
# Si drift détecté, autogen une nouvelle migration
argus-env/bin/alembic revision --autogenerate -m "fix drift"
```

---

## Variables d'environnement

| Variable | Effet |
|---|---|
| `ARGUS_DB_URL` | Override `general.db_url`. Lu par Alembic + h4wk3y3 runtime. |
| `ARGUS_TEST_POSTGRES_URL` | Override DSN pour les tests sans toucher h4wk3y3.yaml. |
