"""h4wk3y3 - Unified Logger"""

import logging
import sys
from pathlib import Path
from typing import Optional


COLORS = {
    'DEBUG':    '\033[36m',   # Cyan
    'INFO':     '\033[32m',   # Green
    'WARNING':  '\033[33m',   # Yellow
    'ERROR':    '\033[31m',   # Red
    'CRITICAL': '\033[35m',   # Magenta
    'RESET':    '\033[0m',
    'BOLD':     '\033[1m',
    'DIM':      '\033[2m',
}


class ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        color  = COLORS.get(record.levelname, '')
        reset  = COLORS['RESET']
        dim    = COLORS['DIM']
        bold   = COLORS['BOLD']

        # Module tag in brackets
        module = f"[{record.name}]" if record.name != 'root' else '[argus]'

        # Ensure asctime is available
        if not hasattr(record, 'asctime'):
            record.asctime = self.formatTime(record, self.datefmt)

        msg = record.getMessage()
        return f"{dim}{record.asctime}{reset} {color}{bold}{record.levelname:<8}{reset} {dim}{module:<25}{reset} {msg}"


def get_logger(
    name: str,
    level: str = "INFO",
    log_file: Optional[str] = None
) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(ColorFormatter(fmt='%(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(ch)

    # File handler (optional)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter(
            fmt='%(asctime)s %(levelname)-8s [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(fh)

    logger.propagate = False
    return logger



def banner():
    bold  = COLORS['BOLD']
    green = COLORS['INFO']
    reset = COLORS['RESET']
    dim   = COLORS['DIM']
    print(f"\n{bold}{green}  👁  h4wk3y3{reset}  {dim}· advanced reconnaissance framework{reset}")
    print(f"{dim}  ────────────────────────────────────────────────────{reset}\n")
