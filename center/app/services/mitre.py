"""Map honeypot events to MITRE ATT&CK techniques (feature #2).

Rule-based classifier: given an event (type + payload), return a technique id.
Intentionally lightweight and transparent — enough to turn raw events into
ATT&CK-tagged intelligence across the fleet.
"""
from __future__ import annotations

# technique_id -> (name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1049": ("System Network Connections Discovery", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
}

# first-token / substring rules for shell commands
_CMD_RULES: list[tuple[tuple[str, ...], str]] = [
    (("whoami", "id", "groups"), "T1033"),
    (("uname", "hostname", "lsb_release", "cat /etc/os-release", "cat /etc/issue"), "T1082"),
    (("ls", "find", "dir", "tree", "pwd"), "T1083"),
    (("cat /etc/passwd", "cat /etc/group", "getent"), "T1087"),
    (("cat /etc/shadow", "cat /root/.aws", "cat /root/.ssh", "unshadow"), "T1552"),
    (("mimikatz", "lsass", "/etc/shadow"), "T1003"),
    (("ps", "top", "htop"), "T1057"),
    (("netstat", "ss ", "ss\n", "lsof", "tcpdump"), "T1049"),
    (("wget", "curl", "tftp", "scp", "ftpget", "nc "), "T1105"),
    (("ssh ", "ssh\n", "sshpass"), "T1021"),
    (("virt-what", "systemd-detect-virt", "dmidecode", "/proc/cpuinfo", "/proc/1/cgroup"), "T1497"),
]


def classify(event_type: str, payload: dict | None) -> str | None:
    payload = payload or {}
    if event_type == "scan":
        return "T1046"
    if event_type == "connect":
        return "T1046"
    if event_type == "auth_attempt":
        return "T1110"
    if event_type == "token_trigger":
        return "T1552"
    if event_type == "http_request":
        return "T1190" if payload.get("method") == "POST" else "T1046"
    if event_type == "command":
        cmd = str(payload.get("command", "")).strip().lower()
        for needles, tid in _CMD_RULES:
            if any(n.strip().lower() in cmd or cmd.startswith(n.strip().lower()) for n in needles):
                return tid
        return "T1059"  # generic command execution
    return None


def describe(technique_id: str | None) -> dict | None:
    if not technique_id or technique_id not in TECHNIQUES:
        return None
    name, tactic = TECHNIQUES[technique_id]
    return {"id": technique_id, "name": name, "tactic": tactic}
