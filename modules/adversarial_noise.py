"""
MODULE 7 — ADVERSARIAL NOISE
Injects subtle statistical noise into YOUR OWN server responses
to corrupt attacker AI reconnaissance models.
Never touches attacker machines — only affects what your server sends back.
"""

import random
import hashlib


def add_noise_to_headers(ip: str, headers: dict) -> dict:
    """
    Slightly alter HTTP response headers for suspicious IPs.
    Attacker AI builds wrong fingerprint of your server.
    """
    noisy = headers.copy()
    seed  = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
    random.seed(seed)

    # Randomly swap server version numbers
    if "Server" in noisy:
        versions = ["Apache/2.4.41", "nginx/1.18.0", "Apache/2.2.34", "nginx/1.14.2"]
        noisy["Server"] = random.choice(versions)

    # Add fake headers that confuse fingerprinting tools
    fake_headers = {
        "X-Powered-By":    random.choice(["PHP/7.4.3", "ASP.NET", "Express", "Django/3.2"]),
        "X-Frame-Options": random.choice(["DENY", "SAMEORIGIN", "ALLOW-FROM fake.internal"]),
        "X-Request-ID":    hashlib.md5(str(random.random()).encode()).hexdigest()[:12],
    }
    noisy.update(fake_headers)

    return noisy


def add_noise_to_port_response(ip: str, port: int, response: str) -> str:
    """
    Slightly alter service banners for suspicious IPs.
    Makes their port scanner report subtly wrong service versions.
    """
    seed = int(hashlib.md5(f"{ip}:{port}".encode()).hexdigest()[:8], 16)
    random.seed(seed)

    # Alter version numbers in banner
    # e.g. OpenSSH_8.2 becomes OpenSSH_7.9 for this specific IP
    version_swaps = {
        "OpenSSH_8.2": random.choice(["OpenSSH_7.6", "OpenSSH_8.0", "OpenSSH_7.9"]),
        "Apache/2.4":  random.choice(["Apache/2.2", "Apache/2.3", "Apache/2.4"]),
        "nginx/1.18":  random.choice(["nginx/1.14", "nginx/1.16", "nginx/1.20"]),
        "5.7.38":      random.choice(["5.6.50", "5.7.30", "8.0.26"]),
    }

    noisy_response = response
    for real, fake in version_swaps.items():
        if real in noisy_response:
            noisy_response = noisy_response.replace(real, fake)

    return noisy_response


def add_noise_to_file_metadata(ip: str, filepath: str, size: int, mtime: float) -> dict:
    """
    Return slightly wrong file metadata for suspicious IPs.
    Their file system reconnaissance builds a wrong picture.
    """
    seed = int(hashlib.md5(f"{ip}:{filepath}".encode()).hexdigest()[:8], 16)
    random.seed(seed)

    # Shift size by small random amount
    fake_size = size + random.randint(-512, 512)
    if fake_size < 0:
        fake_size = size

    # Shift modification time by small random amount
    fake_mtime = mtime + random.randint(-86400, 86400)  # +/- 1 day

    return {
        "size":  fake_size,
        "mtime": fake_mtime,
        "real_size":  size,
        "real_mtime": mtime,
    }
