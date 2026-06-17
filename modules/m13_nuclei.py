"""
Argus V2 - Module 08: Targeted Nuclei Scanner
Tech-aware template selection — scan what matters based on M02 data
"""

import asyncio
import json
import time
from pathlib import Path
from typing import List, Dict, Set, Optional
from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


# Technology → Nuclei template tags mapping
TECH_TEMPLATE_MAP: Dict[str, List[str]] = {
    "WordPress":     ["wordpress", "wp"],
    "Drupal":        ["drupal"],
    "Joomla":        ["joomla"],
    "Magento":       ["magento"],
    "Laravel":       ["laravel"],
    "Django":        ["django"],
    "Spring":        ["spring", "springboot"],
    "Tomcat":        ["apache-tomcat", "tomcat"],
    "Nginx":         ["nginx"],
    "Apache":        ["apache", "apache-httpd"],
    "IIS":           ["iis", "microsoft"],
    "Jenkins":       ["jenkins"],
    "GitLab":        ["gitlab"],
    "Grafana":       ["grafana"],
    "Kibana":        ["kibana"],
    "Elasticsearch": ["elasticsearch"],
    "phpMyAdmin":    ["phpmyadmin"],
    "Adminer":       ["adminer"],
    "SonarQube":     ["sonarqube"],
    "Prometheus":    ["prometheus"],
    "RabbitMQ":      ["rabbitmq"],
    "PHP":           ["php"],
    "Node.js":       ["nodejs", "express"],
    "AWS":           ["aws", "amazon"],
    "Azure":         ["azure"],
    "Shopify":       ["shopify"],
    # additions (2026-05-07)
    "Vue.js":        ["vuejs", "vue"],
    "React":         ["react"],
    "Next.js":       ["nextjs", "next"],
    "Nuxt":          ["nuxtjs", "nuxt"],
    "Bootstrap":     ["bootstrap"],
    "MySQL":         ["mysql"],
    "PostgreSQL":    ["postgres", "postgresql"],
    "MongoDB":       ["mongodb"],
    "Redis":         ["redis"],
    "FastAPI":       ["fastapi"],
    "Flask":         ["flask"],
    "Express":       ["express"],
    "Strapi":        ["strapi"],
    "Ghost":         ["ghost"],
    "Symfony":       ["symfony"],
    "Rails":         ["rails", "ruby-on-rails"],
    "Yii":           ["yii"],
    "ColdFusion":    ["coldfusion"],
    "WebLogic":      ["weblogic"],
    "WebSphere":     ["websphere"],
    "JBoss":         ["jboss"],
    "Confluence":    ["confluence", "atlassian"],
    "Jira":          ["jira", "atlassian"],
    "Bitbucket":     ["bitbucket", "atlassian"],
    "Gitea":         ["gitea"],
    "Nextcloud":     ["nextcloud"],
    "Owncloud":      ["owncloud"],
    "Tableau":       ["tableau"],
    "Cisco":         ["cisco"],
    "Fortinet":      ["fortinet", "fortigate"],
    "Citrix":        ["citrix"],
    "F5":            ["f5", "bigip"],
    "VMware":        ["vmware"],
    "vCenter":       ["vcenter", "vmware"],
}

SEV_MAP = {
    'critical': Severity.CRITICAL,
    'high':     Severity.HIGH,
    'medium':   Severity.MEDIUM,
    'low':      Severity.LOW,
    'info':     Severity.INFO,
}


class NucleiModule(BaseModule):

    MODULE_ID   = "m13"
    MODULE_NAME = "Nuclei Scanner"

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('nuclei', default={})
        out_dir = self._output_dir(target)

        if not target.live_hosts:
            self.log.warning("No live hosts — skipping Nuclei scan")
            return

        # ── Collect live URLs ─────────────────────────────────
        live_urls = [h.get('url', '') for h in target.live_hosts if h.get('url')]
        # Scope filter — never scan a host that isn't in scope, even if it
        # somehow leaked into live_hosts. This is defense-in-depth; m02/m03
        # should already have filtered, but a misconfigured wildcard or a
        # CNAME pointing to a third-party can drag an external host in.
        live_urls = self._filter_in_scope(target, live_urls, label="hosts")
        if not live_urls:
            self.log.warning("No in-scope hosts after scope filter — skipping Nuclei scan")
            return

        # ── Recovered targets (m11 source-map recovery) ───────
        # Hosts / API base URLs extracted from recovered first-party source —
        # backends the public crawl never reached. Scope-filtered here so an
        # out-of-scope leak (e.g. a raw-IP backend) is logged, not scanned.
        rec_urls, rec_dropped = self._load_recovered_targets(out_dir, target)
        if rec_dropped:
            self.log.info(f"   recovered targets: {rec_dropped} out-of-scope (logged, not scanned)")
        if rec_urls:
            new = [u for u in rec_urls if u not in set(live_urls)]
            if new:
                self.log.info(f"   +{len(new)} recovered in-scope target(s) added to Nuclei scan")
                live_urls.extend(new)

        # ── Collect detected technologies ─────────────────────
        all_techs: Set[str] = set()
        for host in target.live_hosts:
            techs = host.get('technologies', [])
            if isinstance(techs, list):
                all_techs.update(techs)

        self.log.info(
            f"⚡ Nuclei scan — {len(live_urls)} hosts | "
            f"technologies: {', '.join(sorted(all_techs)) or 'none detected'}"
        )

        # ── Build template list ───────────────────────────────
        # Default profile: surface-only — misconfigurations + exposures.
        # Excludes CVE/default-login/intrusive entirely (see exclude_tags).
        # Goal: fast common checks, NOT an exploit/CVE scanner. Operator
        # who wants CVE coverage adds it via custom_templates_dir or
        # extends `always_run` in h4wk3y3.yaml.
        tags:      Set[str] = set()
        templates: List[str] = list(cfg.get('always_run', [
            'http/misconfiguration/', 'http/exposures/',
            # exposed-panels was previously in this list. Dropped from the
            # default: ~1700 templates, mostly login-page detection that
            # rarely yields actionable findings on a surface sweep and
            # accounted for the bulk of the 60k requests that timed m13
            # out on una.bj. Add back per-target via h4wk3y3.yaml if needed.
        ]))

        # High-impact info templates: specific tags only, surface-flavoured.
        # `kibana, jenkins-unauth, gitea-unauth` were dropped — they're
        # CVE/auth-bypass attempts, not surface checks.
        if cfg.get('high_impact_info', True):
            tags.update({
                'config-leak', 'env', 'exposure', 'git', 'svn', 'backup',
                'dotenv', 'secret', 'token', 'apikey', 'graphql-ide',
                'wp-config', 'phpinfo', 'sourcemap', 'debug',
            })

        if cfg.get('targeted_scanning', True):
            for tech in all_techs:
                for pattern, tag_list in TECH_TEMPLATE_MAP.items():
                    if pattern.lower() in tech.lower():
                        tags.update(tag_list)

        # ── Custom templates directory ────────────────────────
        custom_dir = cfg.get('custom_templates_dir', './data/nuclei-templates')
        custom_templates: List[str] = []
        if custom_dir:
            custom_path = Path(custom_dir)
            if custom_path.is_dir():
                custom_templates = [
                    str(p) for p in sorted(custom_path.rglob('*.yaml'))
                ]
                if custom_templates:
                    self.log.info(f"   Custom templates: {len(custom_templates)} from {custom_dir}")

        self.log.info(f"   Templates: {templates} | Tags: {sorted(tags)}")

        # ── Write host list ───────────────────────────────────
        hosts_tmp = out_dir / "nuclei_hosts.tmp"
        hosts_tmp.write_text('\n'.join(live_urls))

        # ── Run Nuclei ────────────────────────────────────────
        severity_list = list(cfg.get('severity', ['medium', 'high', 'critical']))
        # If high-impact info templates are enabled, allow nuclei to emit info too.
        if cfg.get('high_impact_info', True) and 'info' not in severity_list:
            severity_list.append('info')
        severity      = ','.join(severity_list)
        # OPSEC default: 10 req/s. Aligned with the project-wide OPSEC policy
        # (CLAUDE.md): nuclei -rate-limit 10 (15 if no WAF), drop to 5 under
        # WAF or in stealth mode. Operator can still override via
        # nuclei.rate_limit in YAML if running against an authorised target
        # with explicit permission to scan faster.
        rate_limit = int(cfg.get('rate_limit', 10))
        waf_detected = any(h.get('waf') for h in target.live_hosts)
        if waf_detected:
            rate_limit = min(rate_limit, 5)
            self.log.info("   WAF detected on at least one host — capping rate-limit at 5 req/s")
        if self.stealth:
            rate_limit = min(rate_limit, 5)
            self.log.info("   Stealth mode — capping rate-limit at 5 req/s")
        # Honour scope-level max_rps restrictions (was informational only).
        scope = getattr(target, 'scope', None)
        if scope is not None:
            scope_rps = scope.tightest_max_rps(live_urls)
            if scope_rps and scope_rps < rate_limit:
                rate_limit = scope_rps
                self.log.info(f"   scope max_rps={scope_rps} — capping nuclei rate-limit")
        self.log.info(f"   nuclei rate-limit: {rate_limit} req/s")
        concurrency   = cfg.get('concurrency', 25)
        timeout       = cfg.get('timeout', 10)
        retries       = cfg.get('retries', 2)
        # Default nuclei -max-host-error = 30: after 30 network errors on a
        # host, that host is dropped from the rest of the scan. With CVE
        # templates (~3000+) and any moderately slow network, we hit 30
        # errors per host in <1 minute and end up scanning ~10% of templates
        # with 0 findings. Bump to 200 (or 0 to disable). Most legit scans
        # complete in <5min/host, so 200 errors = ~3min of timeouts before
        # we give up — generous enough to cover transient network blips.
        max_host_err  = cfg.get('max_host_error', 200)
        # Default exclude_tags broadened to enforce the "surface-only"
        # contract: even when `targeted_scanning` matches a tech tag like
        # `wordpress`, the operator gets the misconfig/exposure subset —
        # never CVE/default-login/intrusive templates.
        exclude_tags  = cfg.get('exclude_tags', [
            'dos', 'fuzz', 'intrusive', 'cve', 'default-login',
        ])
        nuclei_output = out_dir / "nuclei_findings.json"
        nuclei_stderr = out_dir / "nuclei_stderr.log"

        # Nuclei v3.x renamed `-json` → `-jsonl` (the old long flag was
        # removed entirely; `-j` / `-jsonl` are accepted). Using `-json`
        # makes nuclei exit 2 in <2s with "flag provided but not defined".
        cmd = [
            'nuclei',
            '-l',           str(hosts_tmp),
            '-severity',    severity,
            '-rate-limit',  str(rate_limit),
            '-c',           str(concurrency),
            '-timeout',     str(timeout),
            '-retries',     str(retries),
            '-silent',
            '-jsonl',
            '-o',           str(nuclei_output),
            # Progress on stderr — drained live and parsed.
            '-stats', '-stats-json', '-stats-interval', '30',
        ]

        # Host-error skip threshold (or fully disable).
        if max_host_err == 0:
            cmd += ['-no-mhe']
        else:
            cmd += ['-max-host-error', str(max_host_err)]

        # Explicit DNS resolvers + system fallback. m13 used to inherit
        # whatever /etc/resolv.conf had; in pipeline runs after m10/m11
        # fetched thousands of URLs, the resolver could be throttled and
        # nuclei would see massive DNS-failure rates → many templates
        # short-circuit and the run finishes "successfully" with 0 findings
        # in ~163s. Passing -r + -sr stabilises this.
        resolvers_file = cfg.get('resolvers') or self.config.get(
            'subdomain', 'resolvers', default='./data/resolvers/resolvers.txt'
        )
        if resolvers_file and Path(resolvers_file).is_file():
            cmd += ['-r', str(resolvers_file), '-sr']
        else:
            cmd += ['-sr']

        # Templates (built-in + custom)
        for tmpl in templates + custom_templates:
            cmd += ['-t', tmpl]

        # Tags
        if tags:
            cmd += ['-tags', ','.join(sorted(tags))]

        # Exclude tags
        if exclude_tags:
            cmd += ['-exclude-tags', ','.join(exclude_tags)]

        # Drain stderr live: write to disk for post-mortem AND parse JSON
        # progress lines for periodic in-log surfacing. Avoids any pipe
        # buffer issue (nuclei can emit 1000s of error/warning lines on
        # unreachable hosts) and gives the operator a heartbeat instead
        # of 5–15 minutes of silence.
        last_stats: Dict = {}

        async def _drain_stderr(stream, file_path: Path, log) -> None:
            nonlocal last_stats
            last_log_t = 0.0
            with open(file_path, 'wb') as f:
                while True:
                    try:
                        line = await stream.readline()
                    except (ValueError, asyncio.LimitOverrunError):
                        # Single line > 64KB buffer — drop and continue.
                        continue
                    if not line:
                        break
                    f.write(line)
                    txt = line.decode('utf-8', errors='ignore').strip()
                    if not txt or not txt.startswith('{'):
                        continue
                    try:
                        obj = json.loads(txt)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict) and 'matched' in obj and 'duration' in obj:
                        last_stats = obj
                        now = time.time()
                        if now - last_log_t > 30:
                            log.info(
                                f"   nuclei progress: {obj.get('percent','?')}%"
                                f" | matched={obj.get('matched',0)}"
                                f" | errors={obj.get('errors',0)}"
                                f" | rps={obj.get('rps','?')}"
                                f" | requests={obj.get('requests','?')}/{obj.get('total','?')}"
                                f" | duration={obj.get('duration','?')}"
                            )
                            last_log_t = now

        _t0 = time.time()
        proc: Optional[asyncio.subprocess.Process] = None
        drain_task: Optional[asyncio.Task] = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            drain_task = asyncio.create_task(_drain_stderr(proc.stderr, nuclei_stderr, self.log))
            await asyncio.wait_for(proc.wait(), timeout=1800)
            await drain_task
            elapsed = time.time() - _t0
            if proc.returncode != 0:
                tail = ''
                try:
                    tail = nuclei_stderr.read_text(errors='ignore').strip().splitlines()[-3:]
                    tail = ' | '.join(tail)
                except Exception:
                    pass
                self.log.warning(
                    f"Nuclei exit={proc.returncode} after {elapsed:.1f}s — stderr tail: {tail[:500]}"
                )
            elif elapsed < 5 and not last_stats:
                # Sanity check: a real scan against N hosts × N templates
                # never finishes in <5s.
                self.log.warning(
                    f"Nuclei exited in {elapsed:.1f}s with no progress event "
                    f"(suspicious — see {nuclei_stderr})"
                )
        except asyncio.TimeoutError:
            self.log.warning("Nuclei scan timed out (30 min) — terminating")
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            if drain_task:
                drain_task.cancel()
                try:
                    await drain_task
                except (asyncio.CancelledError, Exception):
                    pass
        except Exception as e:
            self.log.error(f"Nuclei error: {e}")
            if drain_task:
                drain_task.cancel()
                try:
                    await drain_task
                except (asyncio.CancelledError, Exception):
                    pass

        hosts_tmp.unlink(missing_ok=True)

        # ── Parse results ─────────────────────────────────────
        findings_data: List[dict] = []
        if nuclei_output.exists():
            for line in nuclei_output.read_text().splitlines():
                try:
                    findings_data.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        self.log.info(f"   Nuclei raw findings: {len(findings_data)}")

        # Add findings
        for item in findings_data:
            info     = item.get('info', {})
            sev_str  = info.get('severity', 'info').lower()
            sev      = SEV_MAP.get(sev_str, Severity.INFO)

            f = Finding(
                type=FindingType.NUCLEI_FINDING,
                target=item.get('host', target.domain),
                url=item.get('matched-at') or item.get('host'),
                title=info.get('name', 'Nuclei finding'),
                severity=sev,
                confidence=0.9,
                evidence=item.get('matched-at', ''),
                tags=info.get('tags', []),
                metadata={
                    'template_id': item.get('template-id'),
                    'template':    item.get('template'),
                    'type':        item.get('type'),
                    'matcher':     item.get('matcher-name'),
                    'curl_command': item.get('curl-command', ''),
                    'description': info.get('description', ''),
                    'reference':   info.get('reference', []),
                    'cvss_score':  info.get('classification', {}).get('cvss-score'),
                    'cve_id':      info.get('classification', {}).get('cve-id', []),
                }
            )
            self._add_finding(target, f)

        # Severity breakdown for the summary line.
        sev_counts: Dict[str, int] = {}
        for x in findings_data:
            s = (x.get('info', {}).get('severity') or 'info').lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        sev_str = ' '.join(f"{k}={v}" for k, v in
                           sorted(sev_counts.items(),
                                  key=lambda kv: ['critical','high','medium','low','info','unknown'].index(kv[0])
                                                if kv[0] in ['critical','high','medium','low','info','unknown'] else 99))

        # Progress recap (final stats line from stderr).
        progress = ''
        if last_stats:
            progress = (
                f" | scanned={last_stats.get('hosts','?')} hosts"
                f" | requests={last_stats.get('requests','?')}/{last_stats.get('total','?')}"
                f" | errors={last_stats.get('errors',0)}"
                f" | duration={last_stats.get('duration','?')}"
            )

        self.log.info(
            f"✅ M08 done — {len(findings_data)} Nuclei findings"
            f" [{sev_str or 'none'}]{progress}"
        )
