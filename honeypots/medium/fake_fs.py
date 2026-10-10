"""A tiny synthetic filesystem / shell for the fake-SSH session.

Just enough to look like a real Ubuntu box for a few commands. Everything is
canned; nothing touches the real host.
"""
from __future__ import annotations

# Honeytoken (FR-A6): a canary credential file. Reading it should never happen
# in normal use, so access is a high-signal indicator of compromise.
CANARY_PATHS = {"/root/.aws/credentials"}
CANARY_TOKEN = "AKIAHONEYFORGE0CANARY"

_FS = {
    "/root": ["backup.sh", "notes.txt", ".bash_history", ".aws"],
    "/root/.aws": ["credentials", "config"],
    "/etc": ["passwd", "shadow", "hostname", "os-release"],
    "/var/www": ["index.html", "config.php"],
    "/home": ["ubuntu"],
    "/home/ubuntu": ["todo.txt"],
}

_FILES = {
    "/root/notes.txt": "TODO: rotate db creds, finish migration to new host\n",
    "/root/backup.sh": "#!/bin/bash\nrsync -az /var/www backup@10.0.0.9:/srv/\n",
    "/etc/hostname": "app-prod-01\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nVERSION_ID="22.04"\n',
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    ),
    "/var/www/config.php": "<?php $db_pass = 'REDACTED'; // see vault\n",
    "/home/ubuntu/todo.txt": "- patch openssl\n- review firewall rules\n",
    "/root/.aws/config": "[default]\nregion = us-east-1\n",
    "/root/.aws/credentials": (
        f"[default]\naws_access_key_id = {CANARY_TOKEN}\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ),
}


class FakeShell:
    def __init__(self, user: str = "root"):
        self.user = user
        self.host = "app-prod-01"
        self.cwd = "/root" if user == "root" else f"/home/{user}"

    def prompt(self) -> str:
        who = "#" if self.user == "root" else "$"
        short = self.cwd.replace(f"/home/{self.user}", "~").replace("/root", "~")
        return f"{self.user}@{self.host}:{short}{who}"

    def resolve(self, path: str) -> str:
        return self._abspath(path)

    def _abspath(self, path: str) -> str:
        if not path or path == ".":
            return self.cwd
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        if path == "..":
            return "/".join(self.cwd.split("/")[:-1]) or "/"
        return f"{self.cwd.rstrip('/')}/{path}"

    def run(self, line: str) -> str:
        parts = line.split()
        if not parts:
            return ""
        cmd, args = parts[0], parts[1:]
        if cmd == "whoami":
            return self.user
        if cmd == "id":
            uid = 0 if self.user == "root" else 1000
            return f"uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({self.user})"
        if cmd == "pwd":
            return self.cwd
        if cmd in ("uname",):
            return "Linux app-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        if cmd == "hostname":
            return self.host
        if cmd == "ls":
            target = self._abspath(args[-1]) if args and not args[-1].startswith("-") else self.cwd
            entries = _FS.get(target)
            return "  ".join(entries) if entries else ""
        if cmd == "cd":
            target = self._abspath(args[0]) if args else f"/home/{self.user}"
            if target in _FS or target == "/":
                self.cwd = target
                return ""
            return f"bash: cd: {args[0] if args else ''}: No such file or directory"
        if cmd == "cat":
            if not args:
                return ""
            path = self._abspath(args[0])
            if path in _FILES:
                return _FILES[path].rstrip("\n")
            return f"cat: {args[0]}: No such file or directory"
        if cmd in ("exit", "logout", "quit"):
            return "__EXIT__"
        if cmd == "help":
            return "available: ls cd cat pwd whoami id uname hostname exit"
        return f"{cmd}: command not found"
