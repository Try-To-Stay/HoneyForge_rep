"""Seed a demo operator and example profiles.

Idempotent: safe to run repeatedly. Credentials come from env
(SEED_OPERATOR_USER / SEED_OPERATOR_PASSWORD), defaulting to the values in
.env.example — never hard-coded secrets, never printed to stdout.

Run inside the center container:
    docker compose exec center python scripts/seed.py
"""
from __future__ import annotations

import asyncio
import os

from sqlalchemy import select

from app.db.base import SessionLocal
from app.db.models import Honeypot, Operator, Profile
from app.security.passwords import hash_password, hash_token

OPERATOR_USER = os.getenv("SEED_OPERATOR_USER", "admin")
OPERATOR_PASSWORD = os.getenv("SEED_OPERATOR_PASSWORD", "honeyforge-admin")
LOW_ENROLL_TOKEN = os.getenv("SEED_LOW_ENROLL_TOKEN", "dev-low-enroll-token")
LOW_HONEYPOT_NAME = "honeypot-low-01"

LOW_PROFILE = {
    "name": "Low — generic TCP banners",
    "level": "low",
    "config": {
        "services": [
            {"type": "tcp", "port": 21, "banner": "220 (vsFTPd 3.0.5)"},
            {"type": "tcp", "port": 23, "banner": "\r\nUbuntu 22.04 LTS\r\nlogin: "},
            {"type": "tcp", "port": 3306, "banner": "5.7.42-log"},
        ],
        "logging": {"capture_commands": False},
        "masking": {"beacon_jitter_s": [20, 40], "process_name": "systemd-timesyncd"},
    },
}

MEDIUM_PROFILE = {
    "name": "Medium — fake SSH + HTTP admin",
    "level": "medium",
    "config": {
        "services": [
            {
                "type": "ssh",
                "port": 22,
                "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                "fake_credentials": [{"username": "admin", "password": "admin123"}],
                "fake_fs": "ubuntu-minimal",
            },
            {
                "type": "http",
                "port": 80,
                "server_header": "nginx/1.24.0",
                "admin_path": "/admin",
                "login_template": "generic",
            },
        ],
        "logging": {"capture_commands": True, "mask_passwords": True},
        "masking": {"beacon_jitter_s": [20, 40], "process_name": "systemd-timesyncd"},
    },
}


async def main() -> None:
    async with SessionLocal() as db:
        result = await db.execute(select(Operator).where(Operator.username == OPERATOR_USER))
        operator = result.scalar_one_or_none()
        if operator is None:
            operator = Operator(
                username=OPERATOR_USER,
                password_hash=hash_password(OPERATOR_PASSWORD),
                role="admin",
            )
            db.add(operator)
            await db.flush()
            print(f"created operator '{OPERATOR_USER}'")
        else:
            print(f"operator '{OPERATOR_USER}' already exists")

        profiles: dict[str, Profile] = {}
        for spec in (LOW_PROFILE, MEDIUM_PROFILE):
            exists = await db.execute(select(Profile).where(Profile.name == spec["name"]))
            found = exists.scalar_one_or_none()
            if found is not None:
                profiles[spec["level"]] = found
                print(f"profile '{spec['name']}' already exists")
                continue
            profile = Profile(
                name=spec["name"],
                level=spec["level"],
                config=spec["config"],
                created_by=operator.id,
            )
            db.add(profile)
            await db.flush()
            profiles[spec["level"]] = profile
            print(f"created profile '{spec['name']}'")

        # A Low honeypot with a known enroll token so the honeypot-low container
        # self-enrolls reproducibly on `docker compose up`.
        hp_exists = await db.execute(
            select(Honeypot).where(Honeypot.name == LOW_HONEYPOT_NAME)
        )
        if hp_exists.scalar_one_or_none() is None:
            db.add(
                Honeypot(
                    name=LOW_HONEYPOT_NAME,
                    profile_id=profiles["low"].id,
                    enroll_token_hash=hash_token(LOW_ENROLL_TOKEN),
                    host_label="edge-cache-07",
                    status="unknown",
                )
            )
            print(f"created honeypot '{LOW_HONEYPOT_NAME}'")
        else:
            print(f"honeypot '{LOW_HONEYPOT_NAME}' already exists")

        await db.commit()
    print("seed done")


if __name__ == "__main__":
    asyncio.run(main())
