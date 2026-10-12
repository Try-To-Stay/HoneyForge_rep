"""A synthetic filesystem / shell for the fake-SSH session (Medium).

Everything is canned — nothing touches the real host — but it answers the
commands attackers actually type (systemctl, ps, netstat, mysql, ifconfig,
history, sudo, …) with believable output so the box doesn't give itself away
after one command. For real command execution, use the High honeypot.
"""
from __future__ import annotations

# Honeytoken (FR-A6): a canary credential file. Reading it should never happen
# in normal use, so access is a high-signal indicator of compromise.
CANARY_PATHS = {"/root/.aws/credentials"}
CANARY_TOKEN = "AKIAHONEYFORGE0CANARY"

_FS = {
    "/root": ["backup.sh", "notes.txt", ".bash_history", ".aws", ".ssh"],
    "/root/.aws": ["credentials", "config"],
    "/root/.ssh": ["id_rsa", "id_rsa.pub", "known_hosts", "authorized_keys"],
    "/etc": ["passwd", "shadow", "hostname", "os-release", "mysql", "nginx"],
    "/var/www": ["index.html", "config.php"],
    "/home": ["ubuntu"],
    "/home/ubuntu": ["todo.txt"],
}

_FILES = {
    "/root/notes.txt": "TODO: rotate db creds, finish migration to new host\n",
    "/root/backup.sh": "#!/bin/bash\nrsync -az /var/www backup@10.0.0.9:/srv/\n",
    "/root/.bash_history": (
        "ls -la\ncd /var/www\nmysql -u root -pS3cr3tDB! prod\n"
        "systemctl restart nginx\nscp backup.sh deploy@10.0.0.9:/srv/\n"
        "vi /etc/mysql/my.cnf\nexit\n"
    ),
    "/root/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAA...TRUNCATED...\n-----END OPENSSH PRIVATE KEY-----\n",
    "/root/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7...deploy@ci\n",
    "/etc/hostname": "app-prod-01\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n',
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    ),
    "/etc/shadow": (
        "root:$6$k9Hd2x$Q8mZ3...REDACTED...hashbytes:19700:0:99999:7:::\n"
        "ubuntu:$6$8Jf0a$1pL9...REDACTED...hashbytes:19700:0:99999:7:::\n"
    ),
    "/var/www/config.php": "<?php\n$db_host='localhost';\n$db_user='webapp';\n$db_pass='Wp_Pr0d_2024!';\n",
    "/home/ubuntu/todo.txt": "- patch openssl\n- review firewall rules\n",
    "/root/.aws/config": "[default]\nregion = us-east-1\n",
    "/root/.aws/credentials": (
        f"[default]\naws_access_key_id = {CANARY_TOKEN}\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ),
    "/proc/version": "Linux version 5.15.0-91-generic (buildd@lcy02) (gcc 11.4.0) #101-Ubuntu SMP\n",
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        "processor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
    ),
    "/proc/meminfo": "MemTotal:        4030820 kB\nMemFree:          812340 kB\nMemAvailable:    2563120 kB\n",
}

_PS = (
    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root         1  0.0  0.3 168140 11600 ?       Ss   Jun10   0:12 /sbin/init\n"
    "root       412  0.0  0.1  72308  6204 ?       Ss   Jun10   0:03 /usr/sbin/sshd -D\n"
    "mysql      889  0.1  8.2 1820140 334220 ?     Ssl  Jun10  18:41 /usr/sbin/mysqld\n"
    "www-data  1021  0.0  0.5 142020 20140 ?       S    Jun10   1:12 nginx: worker process\n"
    "root      1120  0.0  0.2  12140  5120 ?       Ss   Jun10   0:00 /usr/sbin/cron -f\n"
    "admin     3310  0.0  0.1  13920  4300 pts/0   Ss   10:02   0:00 -bash\n"
    "admin     3410  0.0  0.1  15680  3600 pts/0   R+   10:05   0:00 ps aux\n"
)

_NETSTAT = (
    "Active Internet connections (servers and established)\n"
    "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
    "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
    "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
    "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
    "tcp        0      0 10.0.0.12:22            10.0.0.9:51234          ESTABLISHED\n"
)

_IFCONFIG = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
    "        inet 10.0.0.12  netmask 255.255.255.0  broadcast 10.0.0.255\n"
    "        ether 02:42:0a:00:00:0c  txqueuelen 1000  (Ethernet)\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
)

_DF = (
    "Filesystem      Size  Used Avail Use% Mounted on\n"
    "/dev/sda1        98G   26G   68G  28% /\n"
    "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
    "/dev/sda15      105M  6.1M   99M   6% /boot/efi\n"
)

_FREE = (
    "               total        used        free      shared  buff/cache   available\n"
    "Mem:            3936        1420         793          12        1722        2503\n"
    "Swap:           2047         128        1919\n"
)

_LAST = (
    "admin    pts/0        10.0.0.9         Mon 10:02   still logged in\n"
    "deploy   pts/1        10.0.0.9         Sun 18:41 - 19:02  (00:21)\n"
    "root     pts/0        10.0.0.9         Sat 09:12 - 09:40  (00:28)\n"
)


def _systemctl_status(svc: str) -> str:
    svc = svc.replace(".service", "")
    known = {"mysql": "MySQL Community Server", "nginx": "A high performance web server",
             "ssh": "OpenBSD Secure Shell server", "cron": "Regular background program processing daemon"}
    if svc not in known:
        return f"Unit {svc}.service could not be found."
    return (
        f"● {svc}.service - {known[svc]}\n"
        f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled; vendor preset: enabled)\n"
        f"     Active: active (running) since Mon 2024-06-10 09:58:01 UTC; 3 days ago\n"
        f"   Main PID: 889 ({svc})\n"
        f"      Tasks: 38 (limit: 4631)\n"
        f"     Memory: 326.4M\n"
    )


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

        # sudo / env-prefix: run the rest as the command.
        if cmd in ("sudo", "doas") and args:
            return self.run(" ".join(args))

        if cmd == "whoami":
            return self.user
        if cmd == "id":
            uid = 0 if self.user == "root" else 1000
            grp = "root" if self.user == "root" else self.user
            extra = ",27(sudo)" if self.user != "root" else ""
            return f"uid={uid}({self.user}) gid={uid}({grp}) groups={uid}({grp}){extra}"
        if cmd == "pwd":
            return self.cwd
        if cmd == "hostname":
            return self.host
        if cmd == "uname":
            if "-a" in args:
                return "Linux app-prod-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 18:10:01 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            if "-r" in args:
                return "5.15.0-91-generic"
            return "Linux"
        if cmd == "arch":
            return "x86_64"
        if cmd == "nproc":
            return "2"
        if cmd == "date":
            return "Mon Jun 13 10:05:23 UTC 2024"
        if cmd == "uptime":
            return " 10:05:23 up 3 days,  0:07,  1 user,  load average: 0.08, 0.03, 0.01"
        if cmd == "echo":
            return " ".join(args).strip("'\"")
        if cmd == "clear":
            return ""

        if cmd == "ls":
            target = self._abspath(args[-1]) if args and not args[-1].startswith("-") else self.cwd
            entries = _FS.get(target)
            if entries is None:
                return f"ls: cannot access '{args[-1] if args else ''}': No such file or directory" if args and not args[-1].startswith("-") else ""
            return "  ".join(entries)
        if cmd == "cd":
            target = self._abspath(args[0]) if args else f"/home/{self.user}"
            if target in _FS or target == "/":
                self.cwd = target
                return ""
            return f"bash: cd: {args[0] if args else ''}: No such file or directory"
        if cmd in ("cat", "less", "more", "head", "tail"):
            paths = [a for a in args if not a.startswith("-")]
            if not paths:
                return ""
            path = self._abspath(paths[0])
            if path in _FILES:
                return _FILES[path].rstrip("\n")
            return f"{cmd}: {paths[0]}: No such file or directory"

        if cmd in ("ps",):
            return _PS
        if cmd == "top":
            return "top - 10:05:24 up 3 days,  load average: 0.08, 0.03, 0.01\n" + _PS
        if cmd in ("netstat",):
            return _NETSTAT
        if cmd == "ss":
            return _NETSTAT
        if cmd in ("ifconfig",):
            return _IFCONFIG
        if cmd == "ip":
            return _IFCONFIG
        if cmd == "df":
            return _DF
        if cmd == "free":
            return _FREE
        if cmd in ("w", "who"):
            return "admin    pts/0    10.0.0.9         10:02    0.00s  0.02s  0.00s -bash"
        if cmd in ("last", "lastlog"):
            return _LAST
        if cmd in ("env", "printenv", "set"):
            return (
                f"USER={self.user}\nHOME=/{'root' if self.user=='root' else 'home/'+self.user}\n"
                "SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "PWD=" + self.cwd + "\nSSH_CONNECTION=10.0.0.9 51234 10.0.0.12 22\n"
            )
        if cmd == "history":
            return _FILES["/root/.bash_history"].rstrip("\n")
        if cmd == "crontab":
            if "-l" in args:
                return "0 2 * * * /root/backup.sh >/var/log/backup.log 2>&1"
            return ""
        if cmd in ("systemctl",):
            if args and args[0] == "status" and len(args) > 1:
                return _systemctl_status(args[1])
            if args and args[0] in ("start", "stop", "restart", "enable", "disable"):
                return ""
            return "UNIT                 LOAD   ACTIVE SUB     DESCRIPTION\nssh.service          loaded active running OpenBSD Secure Shell server\nmysql.service        loaded active running MySQL Community Server\nnginx.service        loaded active running nginx"
        if cmd == "service" and len(args) >= 2 and args[1] == "status":
            return _systemctl_status(args[0])
        if cmd in ("mysql", "mysqladmin"):
            return "ERROR 1045 (28000): Access denied for user '%s'@'localhost' (using password: %s)" % (
                self.user, "YES" if "-p" in line else "NO")
        if cmd in ("psql",):
            return f'psql: error: connection to server failed: FATAL:  password authentication failed for user "{self.user}"'
        if cmd in ("wget", "curl"):
            url = args[-1] if args else "URL"
            return f"--2024-06-13 10:05:25--  {url}\nResolving host... failed: Temporary failure in name resolution."
        if cmd in ("apt", "apt-get", "dpkg", "yum", "dnf"):
            if self.user != "root":
                return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"
            return "Reading package lists... Done\nBuilding dependency tree... Done\nE: Unable to locate package"
        if cmd in ("su",):
            return "su: Authentication failure"
        if cmd in ("passwd",):
            return "passwd: Authentication token manipulation error"
        if cmd == "which":
            return f"/usr/bin/{args[0]}" if args else ""
        if cmd in ("lsb_release",):
            return "Distributor ID:\tUbuntu\nDescription:\tUbuntu 22.04.3 LTS\nRelease:\t22.04\nCodename:\tjammy"
        if cmd in ("exit", "logout", "quit"):
            return "__EXIT__"
        if cmd == "help":
            return "GNU bash, version 5.1.16(1)-release"
        return f"{cmd}: command not found"
