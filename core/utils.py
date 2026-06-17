"""
core/utils.py — shared helpers used across modules.

Centralises:
- _run_cmd: async subprocess capture with timeout, never raises.
- _strip_ansi: strip ANSI color codes from tool output.
- _DNSX_ENV: env block that forces NO_COLOR on ProjectDiscovery tools.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import List, Optional, Tuple


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def strip_ansi(s: str) -> str:
    """Remove ANSI escape sequences — useful when dnsx/httpx force color."""
    return _ANSI_RE.sub('', s)


DNSX_ENV = {**os.environ, 'NO_COLOR': '1', 'TERM': 'dumb'}


async def reap(proc) -> None:
    """Kill *proc* and wait for it if it is still running. Never raises.

    Use in a ``finally`` block around any ``create_subprocess_exec`` that this
    module does NOT route through ``run_cmd`` (e.g. processes writing to a file
    instead of a captured pipe). asyncio cancels the awaiting coroutine on
    timeout but does NOT terminate the child — without this the tool keeps
    running detached, leaking CPU/sockets/FDs for the whole scan.
    """
    if proc is None:
        return
    try:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
    except (ProcessLookupError, Exception):
        pass


async def run_cmd(cmd: List[str], timeout: int = 120,
                  env: Optional[dict] = None,
                  input_data: Optional[bytes] = None) -> Tuple[int, str, str]:
    """
    Run subprocess capturing (rc, stdout, stderr). Never raises.

    Args:
        cmd:        argv list (no shell).
        timeout:    seconds before the child is killed and reaped.
        env:        extra env vars merged over os.environ.
        input_data: optional bytes piped to the child's stdin.

    Returns:
      ( 0, out, err)  → success
      (-1, '', err)   → timeout (child killed + reaped)
      (-2, '', err)   → binary not found
      (-3, '', err)   → other exec error
    """
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **(env or {})},
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=timeout)
        except asyncio.TimeoutError:
            await reap(proc)
            return -1, '', f'timeout after {timeout}s'
        return proc.returncode or 0, out.decode(errors='replace'), err.decode(errors='replace')
    except FileNotFoundError:
        return -2, '', f'binary not found: {cmd[0]}'
    except Exception as e:
        await reap(proc)
        return -3, '', f'exec error: {e}'
