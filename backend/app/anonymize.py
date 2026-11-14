"""
Anonimización de IPs de visitantes HTTP.

Las IPs de SSH son bots atacando → se muestran completas (son las que se
reportan a AbuseIPDB). Las de HTTP pueden ser personas reales visitando
la web → se truncan ANTES de guardarlas, para que la IP completa nunca
llegue a la API, al WebSocket ni a los exports.

  IPv4: 83.45.120.17          → 83.45.120.xxx   (/24 = 256 direcciones)
  IPv6: 2a02:1234:5678:9::1   → 2a02:1234:5678::xxxx  (/48)
"""
import ipaddress


def mask_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "xxx"
    if addr.version == 4:
        a, b, c, _ = ip.split(".")
        return f"{a}.{b}.{c}.xxx"
    net = ipaddress.ip_network(f"{ip}/48", strict=False)
    prefix = net.network_address.exploded.split(":")[:3]
    return ":".join(p.lstrip("0") or "0" for p in prefix) + "::xxxx"


def is_masked(ip: str) -> bool:
    return "xxx" in ip
