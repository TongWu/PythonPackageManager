# -*- coding: utf-8 -*-
"""
Functions for fetching PyPI metadata.
"""
import utils
import logging
import requests
from logging import StreamHandler, Formatter
from datetime import datetime
from utils.SGTUtils import SGTFormatter
# Custom formatter (assumes SGTFormatter is defined elsewhere or should be implemented here)
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from pytz import timezone as ZoneInfo  # for Python <3.9

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger

PYPI_URL_TEMPLATE = "https://pypi.org/pypi/{package}/json"

def GetPyPiInfo(package: str) -> dict | None:
    """
    Fetch metadata from the PyPI JSON API for a given package.

    Args:
        package (str): Name of the package.

    Returns:
        dict | None: JSON response from PyPI if successful, otherwise None.
    """
    url = PYPI_URL_TEMPLATE.format(package=package)
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning(f"Fetch PyPI metadata for {package} failed: {e}")
        return None
