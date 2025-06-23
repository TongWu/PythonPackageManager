import utils
import os
import csv
import base64
import logging
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

def decode_base64_env(var_name: str, default: str = "Unknown") -> str:
    """
    Decode a base64-encoded environment variable into a UTF-8 string.

    Args:
        var_name (str): The name of the environment variable to decode.
        default (str): Fallback value if decoding fails or variable not found.

    Returns:
        str: Decoded string value, or fallback default if not available or decoding fails.
    """
    val = os.getenv(var_name)
    if not val:
        return default

    try:
        return base64.b64decode(val).decode("utf-8")
    except Exception as e:
        logger.warning(f"Failed to decode base64 environment variable '{var_name}': {e}")
        return default

def load_custodian_map(path: str) -> dict:
    """
    Load custodian information from a CSV file.

    Args:
        path (str): Path to the custodian.csv file.

    Returns:
        dict: Mapping of package_name.lower() -> (custodian, package_type)
    """
    mapping = {}
    try:
        with open(path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                pkg = row.get("Package Name", "").strip().lower()
                Custodian = row.get("Custodian", "").strip()
                PkgType = row.get("Package Type", "").strip()
                if pkg:
                    mapping[pkg] = (Custodian, PkgType)
    except Exception as e:
        logger.error(f"Failed to load custodian map: {e}")
    return mapping

def custom_sort_key(row: dict, CustomOrder: dict) -> tuple:
    """
    Generate a composite sorting key for a package report row based on custodian and package type.

    Sorting priority:
        1. Custodian rank (based on external custom order mapping)
        2. Package type: 'Base Package' comes before 'Dependency Package'
        3. Package name in case-insensitive alphabetical order

    Args:
        row (dict): A dictionary representing a single row in the report.
        CustomOrder (dict): Mapping from custodian name to sort rank (e.g. {"Org1": 0, "Org2": 1}).

    Returns:
        tuple: Sorting key as (CustodianRank, package_type_rank, package_name_lower)
    """
    Custodian = row.get("Custodian", "")
    CustodianRank = CustomOrder.get(Custodian, len(CustomOrder))

    type_order = {"Base Package": 0, "Dependency Package": 1}
    PkgType = row.get("Package Type", "")
    PkgTypeRank = type_order.get(PkgType, 2)

    PkgName = row.get("Package Name", "").lower()

    return (CustodianRank, PkgTypeRank, PkgName)
