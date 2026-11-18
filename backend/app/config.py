import os
from pathlib import Path


def _secret(name: str, default: str = "") -> str:
    """Docker secret (/run/secrets/<name en minúsculas>) y, si no existe, la variable de entorno.

    En producción las claves van como Docker secrets (OWASP #12): en environment:
    se verían con docker inspect y en /proc/1/environ. La variable queda como
    respaldo para el modo dev y el backend en local.
    """
    path = Path("/run/secrets") / name.lower()
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return os.getenv(name, default)


class Settings:
    SSH_LOG_PATH: str = os.getenv("SSH_LOG_PATH", "/var/log/auth.log")
    VPS_LAT: float = float(os.getenv("VPS_LAT", "40.4168"))
    VPS_LON: float = float(os.getenv("VPS_LON", "-3.7038"))
    VPS_LABEL: str = os.getenv("VPS_LABEL", "My VPS")
    GEO_PROVIDER: str = os.getenv("GEO_PROVIDER", "ip-api")
    IPINFO_TOKEN: str = _secret("IPINFO_TOKEN")
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
    ABUSEIPDB_API_KEY: str = _secret("ABUSEIPDB_API_KEY")
    SHODAN_API_KEY: str = _secret("SHODAN_API_KEY")
    ABUSE_CACHE_TTL: int = int(os.getenv("ABUSE_CACHE_TTL", "86400"))

    # ── Persistence (SQLite) ──────────────────────────────────
    # Aggregated counters + a rolling window of events. If the path is not
    # writable the backend falls back to an in-memory DB (nothing survives).
    DB_PATH: str = os.getenv("DB_PATH", "/data/siege.db")
    # Days of individual events kept (time-lapse, sankey, restart recovery).
    # Daily aggregates are kept forever.
    EVENT_RETENTION_DAYS: int = int(os.getenv("EVENT_RETENTION_DAYS", "7"))
    DB_FLUSH_INTERVAL: float = float(os.getenv("DB_FLUSH_INTERVAL", "5"))

    # ── Local GeoIP (GEO_PROVIDER=mmdb) ───────────────────────
    # MaxMind GeoLite2 or DB-IP lite .mmdb files (see scripts/fetch_geoip.sh)
    GEOIP_CITY_DB: str = os.getenv("GEOIP_CITY_DB", "/geoip/city.mmdb")
    GEOIP_ASN_DB: str = os.getenv("GEOIP_ASN_DB", "/geoip/asn.mmdb")

    # ── Extra tagging ─────────────────────────────────────────
    # Download the public Tor exit-node list once a day
    TOR_EXIT_LIST: bool = os.getenv("TOR_EXIT_LIST", "true").lower() == "true"
    # GreyNoise community API (optional, only queried when a dossier is opened)
    GREYNOISE_API_KEY: str = _secret("GREYNOISE_API_KEY")
    GREYNOISE_DAILY_LIMIT: int = int(os.getenv("GREYNOISE_DAILY_LIMIT", "40"))
    # Your own hostnames: referrers from them count as "internal"
    OWN_DOMAINS: str = os.getenv("OWN_DOMAINS", "")
    # Usernames tried in order that identify a wordlist (campaign fingerprint)
    CAMPAIGN_PREFIX_LEN: int = int(os.getenv("CAMPAIGN_PREFIX_LEN", "4"))
    # ── Alerting (alerts.py) ──────────────────────────────────
    ALERTS_ENABLED: bool = os.getenv("ALERTS_ENABLED", "true").lower() == "true"
    # Seconds between rule evaluations
    ALERT_INTERVAL: float = float(os.getenv("ALERT_INTERVAL", "30"))
    # An alert is resolved after its condition has been absent this long;
    # only then can the same subject alert again
    ALERT_COOLDOWN: float = float(os.getenv("ALERT_COOLDOWN", "600"))
    ALERT_SCORE_THRESHOLD: int = int(os.getenv("ALERT_SCORE_THRESHOLD", "75"))
    # Minimum events in 5 minutes for a burst (it must ALSO exceed mean + 3σ)
    ALERT_BURST_MIN: int = int(os.getenv("ALERT_BURST_MIN", "100"))
    # Distinct SSH addresses from one country in 10 minutes (and 3x its usual)
    ALERT_COUNTRY_IPS: int = int(os.getenv("ALERT_COUNTRY_IPS", "15"))
    # Distinct accounts tried by one address in 10 minutes
    ALERT_SPRAY_USERS: int = int(os.getenv("ALERT_SPRAY_USERS", "40"))
    ALERT_CAMPAIGN_MIN_IPS: int = int(os.getenv("ALERT_CAMPAIGN_MIN_IPS", "3"))
    # Failed attempts an address needs before its accepted login is an alert
    ALERT_LOGIN_MIN_FAILS: int = int(os.getenv("ALERT_LOGIN_MIN_FAILS", "3"))
    ALERT_EXPLOIT_2XX: bool = os.getenv("ALERT_EXPLOIT_2XX", "true").lower() == "true"
    ALERT_RETENTION_DAYS: int = int(os.getenv("ALERT_RETENTION_DAYS", "90"))
    # Where to send them. Discord and Slack webhook URLs are recognised and
    # get their own format; anything else receives the alert as JSON.
    ALERT_WEBHOOK_URL: str = _secret("ALERT_WEBHOOK_URL")
    ALERT_TELEGRAM_BOT_TOKEN: str = _secret("ALERT_TELEGRAM_BOT_TOKEN")
    ALERT_TELEGRAM_CHAT_ID: str = os.getenv("ALERT_TELEGRAM_CHAT_ID", "")
    # LOW | MEDIUM | HIGH | CRITICAL: the least severe alert worth a message
    ALERT_NOTIFY_MIN_SEVERITY: str = os.getenv("ALERT_NOTIFY_MIN_SEVERITY", "HIGH").upper()

    # Public link shown on the landing screen
    REPO_URL: str = os.getenv("REPO_URL", "https://github.com/jorgearma/siege-map")

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
    def own_domains(self) -> set[str]:
        return {d.strip().lower() for d in self.OWN_DOMAINS.split(",") if d.strip()}

    @property
    def log_path(self) -> Path:
        return Path(self.SSH_LOG_PATH)


settings = Settings()
