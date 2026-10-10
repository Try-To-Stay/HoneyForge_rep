"""Host-side stealth for the agent (MASK-4).

Sets an innocuous process name so the honeypot agent does not stand out in a
process listing (e.g. appears as `systemd-timesyncd`). Best-effort; failures
are ignored. There are no honeypot/c2 marker strings in the process name.
"""
from __future__ import annotations

import ctypes
import logging

log = logging.getLogger("honeyagent.stealth")

PR_SET_NAME = 15


def set_process_name(name: str | None) -> None:
    if not name:
        return
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        buf = ctypes.create_string_buffer(name.encode()[:15])
        libc.prctl(PR_SET_NAME, ctypes.byref(buf), 0, 0, 0)
        log.info("process name set")
    except Exception:  # noqa: BLE001 - non-Linux or restricted; ignore
        pass
