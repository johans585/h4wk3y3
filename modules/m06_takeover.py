"""
Argus V2 - Module 06: Subdomain Takeover Detection
CNAME → vulnerable cloud services + Nuclei takeover templates
"""

import asyncio
import aiohttp
import ssl
import json
import os
import re
import tempfile
from typing import List, Dict, Set, Optional
from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity

from core.utils import strip_ansi as _strip_ansi, DNSX_ENV as _DNSX_ENV  # noqa: E402

# Cloud/CDN nameservers always alive — never flag as dead delegation.
_TRUSTED_NS_SUFFIXES = (
    'cloudflare.com', 'awsdns-', 'azure-dns.com', 'azure-dns.net',
    'azure-dns.org', 'azure-dns.info', 'googledomains.com', 'google.com',
    'gandi.net', 'ovh.net', 'ovh.ca', 'name.com', 'registrar-servers.com',
    'dnsmadeeasy.com', 'dyn.com', 'ns1.com', 'ultradns.com', 'ultradns.net',
    'ultradns.org', 'ultradns.biz', 'ultradns.info', 'akam.net', 'akamai.net',
    'akamaitech.net', 'akamaiedge.net', 'nsone.net', 'verisign-grs.com',
    'rackspace.com', 'digitalocean.com', 'linode.com', 'hetzner.com',
)


# Known vulnerable CNAME → service fingerprints
# Format: (cname_pattern, service_name, fingerprint_in_body)
# References: can-i-take-over-xyz, EdOverflow's takeover-disclosed,
#             Project Discovery nuclei takeover templates.
TAKEOVER_SIGNATURES = [
    # ── AWS ──────────────────────────────────────────────────────────────
    ("s3.amazonaws.com",             "AWS S3",               "NoSuchBucket|The specified bucket does not exist"),
    ("s3-website",                   "AWS S3 Website",       "NoSuchBucket|The specified bucket does not exist"),
    ("s3-accelerate.amazonaws.com",  "AWS S3 Accelerate",    "NoSuchBucket|The specified bucket does not exist"),
    ("elasticbeanstalk.com",         "AWS Elastic Beanstalk","ERROR: The request could not be satisfied"),
    ("amplifyapp.com",               "AWS Amplify",          "404 Not Found|The page is not redirecting properly"),

    # ── Azure ────────────────────────────────────────────────────────────
    ("azurewebsites.net",            "Azure Web Apps",       "404 Web Site not found"),
    ("cloudapp.azure.com",           "Azure Cloud App",      "404 Web Site not found"),
    ("cloudapp.net",                 "Azure",                "404 Web Site not found"),
    ("trafficmanager.net",           "Azure Traffic Manager",""),
    ("blob.core.windows.net",        "Azure Blob",           "PublicAccessNotPermitted|BlobNotFound"),
    ("azureedge.net",                "Azure CDN",            "Resource not found"),
    ("azurecontainer.io",            "Azure Container",      "404 Site Not Found"),

    # ── Google Cloud ─────────────────────────────────────────────────────
    ("appspot.com",                  "GCP App Engine",       "404 Not Found"),
    ("storage.googleapis.com",       "GCS Bucket",           "NoSuchBucket|The specified bucket does not exist"),
    ("ghs.googlehosted.com",         "Google Sites",         ""),

    # ── Modern PaaS (≤2024 takeovers reported) ───────────────────────────
    ("vercel.app",                   "Vercel",               "The deployment could not be found|DEPLOYMENT_NOT_FOUND"),
    ("vercel-dns.com",               "Vercel DNS",           "The deployment could not be found"),
    ("now.sh",                       "Now (legacy Vercel)",  "The deployment could not be found"),
    ("onrender.com",                 "Render",               "Not Found"),
    ("railway.app",                  "Railway",              "Application Error|404"),
    ("up.railway.app",               "Railway",              "Application Error"),
    ("fly.dev",                      "Fly.io",               "Application Error"),
    ("workers.dev",                  "Cloudflare Workers",   "There is nothing here yet|Worker not found"),
    ("pages.dev",                    "Cloudflare Pages",     "404 Not Found"),
    ("supabase.co",                  "Supabase",             "Project not found"),
    ("supabase.io",                  "Supabase",             "Project not found"),
    ("netlify.app",                  "Netlify",              "Not Found|Page Not Found"),
    ("netlify.com",                  "Netlify",              "Not Found|Page Not Found"),
    ("herokuapp.com",                "Heroku",               "No such app|There's nothing here"),
    ("herokudns.com",                "Heroku DNS",           "No such app"),

    # ── Static / hosting ─────────────────────────────────────────────────
    ("github.io",                    "GitHub Pages",         "There isn't a GitHub Pages site here"),
    ("gitlab.io",                    "GitLab Pages",         "404 Page Not Found"),
    ("bitbucket.io",                 "Bitbucket",            "Repository not found"),
    ("pantheonsite.io",              "Pantheon",             "The gods are wise, but do not know of the site"),
    ("ghost.io",                     "Ghost",                "The thing you were looking for is no longer here"),
    ("surge.sh",                     "Surge",                "project not found"),
    ("webflow.io",                   "Webflow",              "The page you are looking for doesn't exist"),
    ("readthedocs.io",               "Read the Docs",        "Maze Found"),
    ("readme.io",                    "ReadMe",               "Project doesnt exist"),
    ("tilda.ws",                     "Tilda",                "Please renew your subscription"),
    ("strikingly.com",               "Strikingly",           "PAGE NOT FOUND"),

    # ── CDN / Edge ───────────────────────────────────────────────────────
    ("fastly.net",                   "Fastly",               "Fastly error: unknown domain"),
    ("incapdns.net",                 "Incapsula CDN",        ""),

    # ── SaaS misc ────────────────────────────────────────────────────────
    ("myshopify.com",                "Shopify",              "Sorry, this shop is currently unavailable"),
    ("zendesk.com",                  "Zendesk",              "Help Center Closed"),
    ("freshdesk.com",                "Freshdesk",            "There is no helpdesk here"),
    ("helpscoutdocs.com",            "HelpScout Docs",       "No settings were found for this company"),
    ("uservoice.com",                "UserVoice",            "This UserVoice subdomain is currently available"),
    ("feedpress.me",                 "FeedPress",            "The feed has not been found"),
    ("statuspage.io",                "StatusPage",           "You are being redirected"),
    ("tumblr.com",                   "Tumblr",               "Whatever you were looking for doesn't currently exist"),
    ("cargocollective.com",          "Cargo Collective",     "404 Not Found"),
    ("airee.ru",                     "Airee",                "Ошибка"),
    ("intercom.help",                "Intercom",             "This page is reserved for artistic use"),
    ("kinsta.com",                   "Kinsta",               "No site for domain"),
    ("wpengine.com",                 "WP Engine",            "The site you were looking for couldn't be found"),
    ("teamwork.com",                 "Teamwork",             "Oops - We didn't find your site"),
    ("smartling.com",                "Smartling",            "Domain is not configured"),
    ("agilecrm.com",                 "Agile CRM",            "Sorry, this page is no longer available"),
    ("activecampaign.com",           "ActiveCampaign",       "We can't find that page!"),
    ("desk.com",                     "Desk.com",             "Please try again or try Desk.com free for 14 days"),
    ("getresponse.com",              "GetResponse",          "With GetResponse Landing Pages"),
    ("hatenablog.com",               "HatenaBlog",           "404 Blog is not found"),
    ("hostpapa.com",                 "HostPapa",             "There is no website configured at this address"),
    ("instapage.com",                "Instapage",            "Looks Like You're Lost"),
    ("launchrock.com",               "LaunchRock",           "It looks like you may have taken a wrong turn"),
    ("ngrok.io",                     "Ngrok",                "Tunnel .* not found"),
    ("ngrok-free.app",               "Ngrok Free",           "Tunnel .* not found"),
    ("simplebooklet.com",            "SimpleBooklet",        "We can't find this <a"),
    ("tave.com",                     "Tave",                 "Error 404 - Page Not Found"),
    ("unbouncepages.com",            "Unbounce",             "The requested URL was not found on this server"),
    ("wishpond.com",                 "Wishpond",             "https://www.wishpond.com/404\\?campaign=true"),
    ("wufoo.com",                    "Wufoo",                "Hmmm....something is not right"),
]


class TakeoverModule(BaseModule):

    MODULE_ID   = "m06"
    MODULE_NAME = "Subdomain Takeover"

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('takeover', default={})
        out_dir = self._output_dir(target)

        # Load CNAME data from M01
        cnames_file = out_dir / "cnames.json"
        cnames: Dict[str, str] = {}
        if cnames_file.exists():
            try:
                cnames = json.loads(cnames_file.read_text())
            except Exception:
                pass

        # Load external redirects from M02 (redirect → external service)
        redirects_file = out_dir / "redirects.json"
        ext_redirects: Dict[str, dict] = {}
        if redirects_file.exists():
            try:
                ext_redirects = json.loads(redirects_file.read_text())
            except Exception:
                pass

        # Also check all subdomains even without known CNAMEs
        all_subs = target.subdomains or []
        self.log.info(f"🎯 Takeover detection — {len(cnames)} CNAMEs + "
                      f"{len(ext_redirects)} redirects + {len(all_subs)} subdomains")

        concurrent = cfg.get('concurrent', 30)
        sem        = asyncio.Semaphore(concurrent)
        findings   = []

        # Phase 1: CNAME-based detection (fast, high confidence)
        cname_results = await self._check_cnames(cnames, sem)
        findings.extend(cname_results)

        # Phase 1b: External redirect detection (M02 data)
        redirect_results = self._check_redirects(ext_redirects)
        findings.extend(redirect_results)

        # Phase 1c: NS delegation takeover (critical — full DNS control)
        ns_results = await self._check_ns_delegation(all_subs)
        findings.extend(ns_results)
        if ns_results:
            self.log.info(f"   NS delegation: {len(ns_results)} potential takeovers")

        # Phase 2: Nuclei takeover templates (if available)
        nuclei_results = await self._run_nuclei_takeover(all_subs)
        findings.extend(nuclei_results)

        # Deduplicate
        seen: Set[str] = set()
        unique_findings = []
        for item in findings:
            key = item.get('subdomain', '') + item.get('service', '')
            if key not in seen:
                seen.add(key)
                unique_findings.append(item)

        (out_dir / "takeovers.json").write_text(json.dumps(unique_findings, indent=2))
        self._save_artefacts(target, "takeover", unique_findings,
                             key_fields=["subdomain", "service"])

        # Add findings
        for item in unique_findings:
            f = Finding(
                type=FindingType.SUBDOMAIN_TAKEOVER,
                target=item['subdomain'],
                url=f"https://{item['subdomain']}",
                title=f"Potential takeover: {item['subdomain']} → {item['service']}",
                severity=Severity.HIGH,
                confidence=item.get('confidence', 0.7),
                evidence=item.get('evidence', ''),
                tags=['takeover', item['service'].lower().replace(' ', '_')],
                metadata=item
            )
            self._add_finding(target, f)

        self.log.info(f"✅ M06 done — {len(unique_findings)} potential takeovers")

    def _check_redirects(self, ext_redirects: Dict[str, dict]) -> List[dict]:
        """
        Flag subdomains that redirect to external services matching takeover signatures.
        This catches cases where no CNAME is set but the HTTP redirect leaks the service.
        """
        results = []
        for subdomain, info in ext_redirects.items():
            final = info.get('final_url', '')
            external = info.get('external_host', '')
            for cname_pattern, service, _ in TAKEOVER_SIGNATURES:
                if cname_pattern.lower() in external.lower():
                    results.append({
                        'subdomain':  subdomain,
                        'cname':      '',
                        'service':    service,
                        'status':     None,
                        'evidence':   f"HTTP redirect → {final} ({service})",
                        'confidence': 0.7,
                        'redirect_chain': info.get('redirect_chain', []),
                    })
                    break
        return results

    async def _check_ns_delegation(self, subdomains: List[str]) -> List[dict]:
        """
        Detect NS delegation takeovers.
        A subdomain with NS records pointing to unreachable/unregistered nameservers
        means an attacker can register the NS domain and control DNS for that subdomain.
        This is more severe than CNAME takeover — gives full DNS control.
        """
        if not subdomains:
            return []
        results = []
        try:
            input_data = '\n'.join(subdomains).encode()
            proc = await asyncio.create_subprocess_exec(
                'dnsx', '-silent', '-nc', '-ns', '-resp',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=_DNSX_ENV,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(input=input_data), timeout=120)
        except Exception as e:
            self.log.debug(f"dnsx NS error: {e}")
            return []

        # Parse: "sub.example.com [ns1.dead-registrar.com,ns2.dead-registrar.com]"
        ns_map: Dict[str, List[str]] = {}
        for line in _strip_ansi(stdout.decode()).splitlines():
            m = re.match(r'^(\S+)\s+\[(.+)\]', line.strip())
            if m:
                host = m.group(1).lower()
                servers = [n.strip().rstrip('.').lower() for n in m.group(2).split(',')]
                # Drop NS that look like ANSI noise (defense in depth).
                servers = [n for n in servers if n and re.match(r'^[a-z0-9.\-]+$', n)]
                if servers:
                    ns_map[host] = servers

        # For each sub with NS delegation, check if NS domains are reachable.
        # Skip cloud/CDN nameservers (cloudflare, awsdns, etc.) — they never go dead.
        for sub, ns_servers in ns_map.items():
            # Trusted NS = no takeover risk
            if all(any(ns.endswith(suf) or suf in ns for suf in _TRUSTED_NS_SUFFIXES)
                   for ns in ns_servers):
                continue

            dead_ns = []
            for ns in ns_servers:
                if any(ns.endswith(suf) or suf in ns for suf in _TRUSTED_NS_SUFFIXES):
                    continue
                ns_domain = '.'.join(ns.split('.')[-2:])
                try:
                    proc2 = await asyncio.create_subprocess_exec(
                        'dnsx', '-silent', '-nc', '-a', '-d', ns_domain,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                        env=_DNSX_ENV,
                    )
                    out2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                    if not _strip_ansi(out2.decode()).strip():
                        dead_ns.append(ns)
                except Exception:
                    # Don't flag on transient errors — only on confirmed empty resolution.
                    pass

            if dead_ns:
                results.append({
                    'subdomain':  sub,
                    'cname':      '',
                    'service':    'NS Delegation',
                    'status':     None,
                    'evidence':   f"NS delegation to unreachable servers: {', '.join(dead_ns)}",
                    'confidence': 0.6,  # downgraded — NS dead != claimable yet
                    'ns_servers': ns_servers,
                    'dead_ns':    dead_ns,
                })
        return results

    async def _check_cnames(self, cnames: Dict[str, str], sem: asyncio.Semaphore) -> List[dict]:
        """Check subdomains with CNAME records pointing to vulnerable services."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout   = aiohttp.ClientTimeout(total=10)

        async def check_one(sess: aiohttp.ClientSession, subdomain: str, cname: str) -> Optional[dict]:
            for cname_pattern, service, body_fingerprint in TAKEOVER_SIGNATURES:
                if cname_pattern.lower() not in cname.lower():
                    continue
                # CNAME matches — now check if the service is actually unclaimed
                async with sem:
                    try:
                        async with sess.get(
                            f"https://{subdomain}",
                            allow_redirects=True
                        ) as resp:
                            body = await resp.text(errors='ignore')
                            if body_fingerprint:
                                patterns = body_fingerprint.split('|')
                                for pat in patterns:
                                    if re.search(pat, body, re.I):
                                        return {
                                            'subdomain': subdomain,
                                            'cname':     cname,
                                            'service':   service,
                                            'status':    resp.status,
                                            'evidence':  f"CNAME → {cname} | Body match: {pat}",
                                            'confidence': 0.9
                                        }
                            else:
                                # No body fingerprint → rely on CNAME alone (lower confidence)
                                return {
                                    'subdomain': subdomain,
                                    'cname':     cname,
                                    'service':   service,
                                    'status':    None,
                                    'evidence':  f"CNAME points to potentially vulnerable service: {cname}",
                                    'confidence': 0.5
                                }
                    except aiohttp.ClientConnectorError:
                        # Connection refused / NXDOMAIN → strong takeover signal
                        return {
                            'subdomain': subdomain,
                            'cname':     cname,
                            'service':   service,
                            'status':    None,
                            'evidence':  f"CNAME → {cname} | Service unreachable (DNS resolves but no response)",
                            'confidence': 0.85
                        }
                    except Exception:
                        pass
            return None

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            tasks = [check_one(sess, sub, cname) for sub, cname in cnames.items()]
            raw   = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in raw if isinstance(r, dict)]

    async def _run_nuclei_takeover(self, subdomains: List[str]) -> List[dict]:
        """Run nuclei takeover templates against all subdomains."""
        if not subdomains:
            return []
        tmp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(f"https://{s}" for s in subdomains))
                tmp_file = f.name

            proc = await asyncio.create_subprocess_exec(
                'nuclei',
                '-l', tmp_file,
                '-t', 'takeovers/',
                '-silent',
                '-json',
                '-severity', 'medium,high,critical',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            if stderr:
                self.log.debug(f"Nuclei takeover stderr: {stderr.decode(errors='ignore')[:500]}")

            results = []
            for line in stdout.decode().splitlines():
                try:
                    item = json.loads(line)
                    results.append({
                        'subdomain': item.get('host', '').replace('https://', '').replace('http://', ''),
                        'service':   item.get('info', {}).get('name', 'Unknown'),
                        'cname':     '',
                        'evidence':  item.get('matched-at', ''),
                        'confidence': 0.95,
                        'nuclei_template': item.get('template-id', '')
                    })
                except json.JSONDecodeError:
                    pass
            return results
        except Exception as e:
            self.log.debug(f"Nuclei takeover error: {e}")
            return []
        finally:
            if tmp_file:
                try:
                    os.unlink(tmp_file)
                except OSError:
                    pass
