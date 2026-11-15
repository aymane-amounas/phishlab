"""ASCII startup banner printed when the PhishLab API boots."""

from __future__ import annotations

import sys

from phishlab import __version__
from phishlab.config import settings

_ART = r"""
  ____  _     _     _     _          _
 |  _ \| |__ (_)___| |__ | |    __ _| |__      ><(((o>
 | |_) | '_ \| / __| '_ \| |   / _` | '_ \   ><(((o>   [@]
 |  __/| | | | \__ \ | | | |__| (_| | |_) |     ><(((o>
 |_|   |_| |_|_|___/_| |_|_____\__,_|_.__/
"""


def banner_text() -> str:
    net = "ENABLED" if settings.network_lookups_enabled else "disabled"
    lines = [
        _ART,
        f"  PhishLab v{__version__}  -  offline-first phishing investigation workbench",
        f"  static analysis: offline   |   network lookups: {net}",
        "  attachments are never executed. untrusted HTML is never rendered.",
        "",
    ]
    return "\n".join(lines)


def print_banner() -> None:
    text = banner_text()
    if sys.stdout.isatty():
        text = f"\033[38;5;39m{text}\033[0m"  # blue when attached to a terminal
    print(text, flush=True)
