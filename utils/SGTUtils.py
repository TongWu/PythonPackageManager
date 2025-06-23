#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Utilities for timezone-aware logging and timestamps."""

from logging import Formatter
from datetime import datetime

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:  # pragma: no cover - fallback for <3.9
    from pytz import timezone as ZoneInfo

SG_TZ = ZoneInfo("Asia/Singapore")

class SGTFormatter(Formatter):
    """Logging formatter that outputs times in Singapore timezone."""

    def formatTime(self, record, datefmt=None):
        ct = datetime.fromtimestamp(record.created, SG_TZ)
        if datefmt:
            return ct.strftime(datefmt)
        return ct.isoformat()


def now_sg() -> datetime:
    """Return current time in Singapore timezone (UTC+8)."""
    return datetime.now(SG_TZ)

