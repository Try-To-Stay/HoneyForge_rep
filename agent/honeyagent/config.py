"""Agent configuration from environment."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class AgentConfig:
    # Disguised base URL of the collector (looks like a CDN host).
    base_url: str = os.getenv("HONEYFORGE_BASE_URL", "https://nginx:8443")
    enroll_token: str = os.getenv("HONEYFORGE_ENROLL_TOKEN", "")
    tls_verify: bool = _bool("AGENT_TLS_VERIFY", False)  # self-signed dev cert by default
    buffer_path: str = os.getenv("AGENT_BUFFER_PATH", "/data/agent-buffer.sqlite")
    beacon_interval_s: int = int(os.getenv("AGENT_BEACON_INTERVAL_S", "15"))
    # Jitter range (Bonus MASK-5); defaults to no jitter on Must.
    jitter_min_s: int = int(os.getenv("AGENT_JITTER_MIN_S", "0"))
    jitter_max_s: int = int(os.getenv("AGENT_JITTER_MAX_S", "0"))
    send_batch: int = int(os.getenv("AGENT_SEND_BATCH", "100"))

    # mTLS (MASK-7): when enabled, the agent pins the CA and presents a client
    # cert issued at enrollment, rotating it before expiry.
    mtls_enabled: bool = _bool("MTLS_ENABLED", False)
    ca_path: str = os.getenv("AGENT_CA_PATH", "/data/ca.crt")
    client_cert_path: str = os.getenv("AGENT_CLIENT_CERT_PATH", "/data/client.crt")
    client_key_path: str = os.getenv("AGENT_CLIENT_KEY_PATH", "/data/client.key")
    cert_renew_margin_s: int = int(os.getenv("AGENT_CERT_RENEW_MARGIN_S", "120"))

    # Disguised paths (Nginx rewrites these to /agent/*).
    path_register: str = "/assets/v3/register"
    path_config: str = "/assets/v3/manifest.json"
    path_collect: str = "/assets/v3/collect"
    path_renew: str = "/assets/v3/renew"
