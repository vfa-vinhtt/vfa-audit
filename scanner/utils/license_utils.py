"""
License classification utilities.
"""
from __future__ import annotations
import re
from typing import Set

# License Classifications
PERMISSIVE_LICENSES: Set[str] = {
    "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense",
    "CC0-1.0", "Python-2.0", "MPL-2.0",
}
WEAK_COPYLEFT_LICENSES: Set[str] = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0"}
STRONG_COPYLEFT_LICENSES: Set[str] = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"}
COMMERCIAL_RESTRICTED: Set[str] = {"CC-BY-NC-4.0", "Commons-Clause", "BUSL-1.1"}

def _normalize_license(s: str) -> str:
    s = str(s).strip().strip('"').strip("'")
    s = re.sub(r"\s+", " ", s)
    s = s.replace("Apache License, Version 2.0", "Apache-2.0")
    return s


# Keyword -> classification, scanned in order (MOST SPECIFIC FIRST). This handles
# both SPDX ids (Apache-2.0, MPL-2.0) and the verbose names tools like pip-licenses
# emit ("Apache Software License", "BSD License", "Python Software Foundation License").
# Order matters: e.g. LGPL/Lesser must precede GPL, and AGPL precedes both.
_LICENSE_KEYWORDS = [
    # commercial / restricted
    ("CC-BY-NC", "restricted"), ("COMMONS CLAUSE", "restricted"), ("COMMONS-CLAUSE", "restricted"),
    ("BUSL", "restricted"), ("BUSINESS SOURCE", "restricted"), ("NON-COMMERCIAL", "restricted"),
    # strong copyleft (Affero / SSPL before the generic GPL match)
    ("AGPL", "strong-copyleft"), ("AFFERO", "strong-copyleft"), ("SSPL", "strong-copyleft"),
    # weak copyleft (LGPL/Lesser/MPL/EPL/CDDL before the generic GPL match)
    ("LGPL", "weak-copyleft"), ("LESSER GENERAL PUBLIC", "weak-copyleft"),
    ("MPL", "weak-copyleft"), ("MOZILLA PUBLIC", "weak-copyleft"),
    ("EPL", "weak-copyleft"), ("ECLIPSE PUBLIC", "weak-copyleft"), ("CDDL", "weak-copyleft"),
    # strong copyleft (generic GPL, after LGPL so it is not caught here)
    ("GPL", "strong-copyleft"), ("GENERAL PUBLIC LICENSE", "strong-copyleft"),
    # permissive
    ("APACHE", "permissive"), ("MIT", "permissive"), ("BSD", "permissive"),
    ("ISC", "permissive"), ("ZLIB", "permissive"), ("ARTISTIC", "permissive"),
    ("BOOST", "permissive"), ("WTFPL", "permissive"),
    ("PYTHON SOFTWARE FOUNDATION", "permissive"), ("PSF", "permissive"), ("PYTHON-2", "permissive"),
    ("UNLICENSE", "permissive"), ("PUBLIC DOMAIN", "permissive"), ("CC0", "permissive"),
]


def _classify_license(license_str: str) -> str:
    norm = _normalize_license(license_str).upper()
    if norm in ("NONE", "UNLICENSED", "SEE LICENSE IN", "PROPRIETARY", "PRIVATE", "", "UNKNOWN"):
        return "no-license"
    for keyword, classification in _LICENSE_KEYWORDS:
        if keyword in norm:
            return classification
    return "unknown"
