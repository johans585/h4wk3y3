"""
Argus V2 - Module 04: Screenshot Capturer
Playwright headless Chromium with thumbnails + metadata
"""

import asyncio
import json
from typing import List, Dict, Optional
from modules.base import BaseModule
from core.models import ScanTarget


class ScreenshotModule(BaseModule):

    MODULE_ID   = "m05"
    MODULE_NAME = "Screenshot Capturer"

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('screenshot', default={})
        out_dir = self._output_dir(target)

        if not target.live_hosts:
            self.log.warning("No live hosts — skipping screenshots")
            return

        try:
            from playwright.async_api import async_playwright
            import playwright as _pw
        except ImportError:
            self.log.warning("Playwright not installed — skipping screenshots")
            return

        # Fix: force le node bundlé du venv (évite le conflit avec python3-playwright système)
        import os
        import pathlib
        _pw_dir  = pathlib.Path(_pw.__file__).parent / "driver"
        _pw_node = _pw_dir / "node"
        if _pw_node.exists():
            # PLAYWRIGHT_NODEJS_PATH = variable officielle pour surcharger le node utilisé
            os.environ["PLAYWRIGHT_NODEJS_PATH"]   = str(_pw_node)
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.expanduser("~/.cache/ms-playwright")
        self.log.debug(f"Playwright node: {_pw_node} | browsers: {os.environ['PLAYWRIGHT_BROWSERS_PATH']}")

        live_urls = [h.get('url', '') for h in target.live_hosts if h.get('url')]
        max_urls  = cfg.get('max_urls', 500)
        urls      = live_urls[:max_urls]

        self.log.info(f"📸 Screenshots — {len(urls)} hosts")

        concurrent = cfg.get('concurrent', 3)   # Playwright = ~200Mo/instance
        # `timeout` = page.goto deadline. `screenshot_timeout` = the screenshot()
        # call itself (separate budget — fonts/network can stall after DOM ready).
        timeout_ms        = cfg.get('timeout', 45) * 1000
        screenshot_ms     = cfg.get('screenshot_timeout', cfg.get('timeout', 45)) * 1000
        networkidle_ms    = cfg.get('networkidle_timeout', 12) * 1000
        width      = cfg.get('width', 1280)
        height     = cfg.get('height', 720)
        quality    = cfg.get('quality', 80)
        thumbnails = cfg.get('thumbnails', True)

        shots_dir = out_dir / "screenshots"
        shots_dir.mkdir(exist_ok=True)
        thumbs_dir = shots_dir / "thumbs"
        if thumbnails:
            thumbs_dir.mkdir(exist_ok=True)

        results: List[Dict] = []
        sem = asyncio.Semaphore(concurrent)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-web-security',
                    '--ignore-certificate-errors',
                ]
            )

            async def capture(url: str) -> Optional[Dict]:
                async with sem:
                    # Init ctx upfront so the except-handler below can `ctx.close()`
                    # even if new_context() itself raises (UnboundLocalError otherwise).
                    ctx = None
                    try:
                        ctx = await browser.new_context(
                            viewport={'width': width, 'height': height},
                            ignore_https_errors=True,
                            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        )
                        page = await ctx.new_page()

                        # Block heavy resources
                        await page.route("**/*.{woff,woff2,ttf,eot,mp4,avi}", lambda r: r.abort())

                        try:
                            await page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)
                        except Exception:
                            pass
                        # Laisse le temps aux redirections JS / SPA de se stabiliser.
                        # On utilise networkidle plutôt que sleep fixe — beaucoup de
                        # pages (OWA, login redirect, SPA) détruisent le contexte
                        # d'exécution sinon → "Execution context was destroyed".
                        try:
                            await page.wait_for_load_state('networkidle', timeout=networkidle_ms)
                        except Exception:
                            try:
                                await page.wait_for_load_state('load', timeout=4000)
                            except Exception:
                                pass

                        # Sanitize filename
                        safe_name = url.replace('://', '_').replace('/', '_').replace(':', '_')
                        safe_name = ''.join(c for c in safe_name if c.isalnum() or c in '_-.')[:100]
                        img_path  = shots_dir / f"{safe_name}.png"

                        # Screenshot d'abord — title best-effort après. Comme ça
                        # une nav qui invalide le context ne perd pas l'image.
                        try:
                            await page.screenshot(path=str(img_path), type='png', full_page=False, timeout=screenshot_ms)
                        except Exception as e:
                            # 1 retry après stabilisation supplémentaire
                            try:
                                await page.wait_for_timeout(800)
                                await page.screenshot(path=str(img_path), type='png', full_page=False, timeout=screenshot_ms)
                            except Exception:
                                raise e

                        title = ''
                        try:
                            title = await page.title()
                        except Exception:
                            # Context destroyed by redirect — fallback to URL hostname
                            try:
                                from urllib.parse import urlparse
                                title = urlparse(url).netloc
                            except Exception:
                                title = url

                        # Thumbnail
                        thumb_path = None
                        if thumbnails and img_path.exists():
                            thumb_path = thumbs_dir / f"{safe_name}_thumb.jpg"
                            try:
                                from PIL import Image
                                img   = Image.open(str(img_path))
                                thumb = img.resize((320, 200), Image.LANCZOS)
                                thumb.save(str(thumb_path), 'JPEG', quality=quality)
                            except Exception:
                                pass

                        await ctx.close()
                        return {
                            'url':        url,
                            'title':      title,
                            'screenshot': str(img_path.name),
                            'thumb':      str(thumb_path.name) if thumb_path else None,
                            'status':     'success'
                        }

                    except Exception as e:
                        self.log.debug(f"Screenshot failed {url}: {e}")
                        if ctx is not None:
                            try:
                                await ctx.close()
                            except Exception:
                                pass
                        return {'url': url, 'status': 'failed', 'error': str(e)}

            tasks   = [capture(url) for url in urls]
            raw     = await asyncio.gather(*tasks, return_exceptions=True)
            results = [r for r in raw if isinstance(r, dict)]

            await browser.close()

        # Save metadata
        (out_dir / "screenshots.json").write_text(json.dumps(results, indent=2))

        success = [r for r in results if r.get('status') == 'success']
        self.log.info(f"✅ M04 done — {len(success)}/{len(urls)} screenshots captured")

        # Note: screenshots are NOT emitted as findings. The metadata is
        # persisted in screenshots.json and served via /api/screenshots/...
        # — the dashboard's Screenshots tab is the source of truth.
