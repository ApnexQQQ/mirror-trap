"""
MODULE 3 — FAKE NETWORK TOPOLOGY
Shows attackers fake internal machines that don't exist.
They waste hours trying to pivot to ghost hosts.
Runs entirely on your own server.
"""

import random
import hashlib


# Fake service banners per port
FAKE_BANNERS = {
    22:   "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    80:   "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n",
    443:  "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
    3306: "5.7.38-MySQL Community Server",
    5432: "PostgreSQL 13.4 on x86_64-pc-linux-gnu",
    6379: "+PONG\r\n",
    8080: "HTTP/1.1 200 OK\r\nServer: Jetty/9.4.z-SNAPSHOT\r\n",
    8443: "HTTP/1.1 200 OK\r\nServer: Tomcat/9.0.56\r\n",
}

# Fake internal IP ranges
FAKE_SUBNETS = [
    "10.0.1.", "10.0.2.", "192.168.1.", "172.16.0."
]


def generate_fake_hosts(seed: str, count: int = 4) -> list:
    """
    Generate believable fake internal hosts.
    Seed = attacker IP so same attacker always sees same fake network.
    """
    random.seed(hashlib.md5(seed.encode()).hexdigest())
    hosts = []

    for i in range(count):
        subnet = random.choice(FAKE_SUBNETS)
        last_octet = random.randint(10, 250)
        ip = f"{subnet}{last_octet}"

        # Pick 2-4 open ports for this fake host
        open_ports = random.sample(list(FAKE_BANNERS.keys()), k=random.randint(2, 4))

        hosts.append({
            "ip":         ip,
            "hostname":   _fake_hostname(ip),
            "open_ports": open_ports,
            "os":         random.choice([
                "Ubuntu 20.04", "CentOS 7", "Debian 11", "Windows Server 2019"
            ]),
            "role": random.choice([
                "database-server", "web-server", "mail-server",
                "backup-server", "admin-panel", "internal-api"
            ])
        })

    return hosts


def get_fake_banner(port: int) -> str:
    """Return fake service banner for a port."""
    return FAKE_BANNERS.get(port, "220 Service Ready\r\n")


def _fake_hostname(ip: str) -> str:
    """Generate believable hostname from IP."""
    prefixes = ["db", "web", "mail", "api", "admin", "backup", "prod", "dev"]
    numbers  = ip.split(".")[-1]
    prefix   = prefixes[int(numbers) % len(prefixes)]
    return f"{prefix}-{numbers}.internal.local"
