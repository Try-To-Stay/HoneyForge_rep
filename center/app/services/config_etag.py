"""Stable etag for a profile config, so the agent refetches only on change."""
from __future__ import annotations

import hashlib
import json


def compute_etag(config: dict) -> str:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]
