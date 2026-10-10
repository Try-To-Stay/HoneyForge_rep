#!/bin/bash
# Run the full attack scenario against the honeypots, so you can watch events
# appear in the dashboard. Attacks originate from inside the honeynet (via the
# low honeypot container), so no host ports need to be exposed.
#
# Usage (on the server, from the project dir):
#   bash scripts/demo-attack.sh
set -e
cd "$(dirname "$0")/.."

# Use prod compose files if present, else plain.
if [ -f docker-compose.prod.yml ]; then
  DC="docker compose -f docker-compose.yml -f docker-compose.prod.yml"
else
  DC="docker compose"
fi

echo "Launching demo attack (watch the dashboard feed)..."
$DC exec -T honeypot-low python3 - <<'PY'
import asyncio, socket, urllib.parse, urllib.request
import asyncssh


async def main():
    # 1) Low honeypot: touch the banner ports -> scan/connect events.
    for p in (21, 23, 3306):
        try:
            s = socket.create_connection(("127.0.0.1", p), 2)
            s.recv(64)
            s.sendall(b"probe\r\n")
            s.close()
        except Exception as e:
            print("low", p, e)
    print("[1/3] Low honeypot: scanned ports 21/23/3306")

    # 2) Medium fake-SSH: brute force (-> brute_force alert), then a real login
    #    and reading the canary credentials (-> honeytoken alert).
    for i in range(6):
        try:
            async with asyncssh.connect(
                "honeypot-medium", 22, username="root", password=f"guess{i}", known_hosts=None
            ):
                pass
        except asyncssh.PermissionDenied:
            pass
    async with asyncssh.connect(
        "honeypot-medium", 22, username="admin", password="admin123", known_hosts=None
    ) as c:
        async with c.create_process(term_type="xterm") as p:
            for cmd in ["whoami", "cat /etc/passwd", "cat /root/.aws/credentials", "exit"]:
                p.stdin.write(cmd + "\n")
            await asyncio.sleep(1.0)
    print("[2/3] Medium fake-SSH: brute force + login + honeytoken read")

    # 3) Medium fake-HTTP admin: a credential POST.
    try:
        data = urllib.parse.urlencode({"username": "administrator", "password": "Spring2024!"}).encode()
        urllib.request.urlopen("http://honeypot-medium:80/admin", data=data, timeout=3)
    except Exception:
        pass
    print("[3/3] Medium fake-HTTP: admin login attempt")


asyncio.run(main())
PY

echo "Done. Events should appear in the dashboard within ~10s (beacon interval)."
