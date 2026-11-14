import os
from pathlib import Path


class Settings:
    SSH_LOG_PATH: str = os.getenv("SSH_LOG_PATH", "/var/log/auth.log")
    VPS_LAT: float = float(os.getenv("VPS_LAT", "40.4168"))
    VPS_LON: float = float(os.getenv("VPS_LON", "-3.7038"))
    VPS_LABEL: str = os.getenv("VPS_LABEL", "My VPS")
    GEO_PROVIDER: str = os.getenv("GEO_PROVIDER", "ip-api")
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")
    BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))
    MAX_EVENTS: int = int(os.getenv("MAX_EVENTS", "10000"))
    GEO_CACHE_TTL: int = int(os.getenv("GEO_CACHE_TTL", "86400"))
    WS_BROADCAST_INTERVAL: float = float(os.getenv("WS_BROADCAST_INTERVAL", "1.0"))
    NGINX_LOG_PATH: str = os.getenv("NGINX_LOG_PATH", "/var/log/nginx/access.log")
    # Varias rutas separadas por coma (una por web). Si está vacía se usa NGINX_LOG_PATH.
    NGINX_LOG_PATHS: str = os.getenv("NGINX_LOG_PATHS", "")
    # Truncar las IPs de HTTP (visitantes reales) antes de guardarlas
    MASK_HTTP_IPS: bool = os.getenv("MASK_HTTP_IPS", "true").lower() == "true"
    # IPs propias que nunca deben aparecer (ej. la de casa). Separadas por coma.
    IGNORE_IPS: str = os.getenv("IGNORE_IPS", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    ABUSE_CACHE_TTL: int = int(os.getenv("ABUSE_CACHE_TTL", "86400"))

    @property
    def THREAT_INTEL_ENABLED(self) -> bool:
        return bool(self.ABUSEIPDB_API_KEY)

    @property
    def nginx_paths(self) -> list[str]:
        raw = self.NGINX_LOG_PATHS or self.NGINX_LOG_PATH
        return [p.strip() for p in raw.split(",") if p.strip()]

    @property
    def ignore_ips(self) -> set[str]:
        return {ip.strip() for ip in self.IGNORE_IPS.split(",") if ip.strip()}

    @property
    def log_path(self) -> Path:
        return Path(self.SSH_LOG_PATH)


settings = Settings()
