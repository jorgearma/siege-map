"""Classify the usernames bots try: what are they hoping to find on the box?"""
import re

CATEGORIES: dict[str, set[str]] = {
    # Default / generic accounts of a fresh server
    "default": {
        "root", "admin", "administrator", "user", "test", "guest", "support",
        "ubuntu", "debian", "centos", "fedora", "ec2-user", "azureuser",
        "operator", "demo", "temp", "backup", "info", "service", "student",
        "user1", "test1", "test2", "admin1", "sysadmin", "superuser", "toor",
    },
    # Routers, cameras, single-board computers
    "iot": {
        "pi", "raspberry", "ubnt", "openwrt", "dietpi", "orangepi", "odroid",
        "vyos", "mikrotik", "telecomadmin", "default", "supervisor", "tech",
        "nvr", "dvr", "hikvision", "dahua", "zyfwp", "cisco", "netgear",
        "mother", "e8ehome", "volumio", "osmc", "lede",
    },
    # Databases and services that create a system account
    "service": {
        "postgres", "mysql", "oracle", "mongodb", "mongo", "redis", "elastic",
        "elasticsearch", "hadoop", "spark", "kafka", "zookeeper", "cassandra",
        "git", "nginx", "apache", "www", "www-data", "tomcat", "ftp", "ftpuser",
        "mail", "postfix", "samba", "nagios", "zabbix", "grafana", "prometheus",
        "kibana", "rabbitmq", "minio", "squid", "odoo", "dspace", "nexus",
        "sonar", "es", "db2inst1", "sftp", "vnc", "weblogic", "jboss",
    },
    # Automation and deployment accounts — usually with sudo
    "devops": {
        "deploy", "deployer", "ansible", "docker", "jenkins", "gitlab",
        "gitlab-runner", "runner", "vagrant", "terraform", "k8s", "kubernetes",
        "ci", "build", "dev", "devops", "developer", "github", "actions",
        "puppet", "chef", "awx", "rancher", "kubeadmin", "ops",
    },
    # Blockchain nodes and miners: a compromised one is immediate money
    "crypto": {
        "solana", "sol", "validator", "ethereum", "eth", "node", "bitcoin",
        "btc", "miner", "mining", "ton", "sui", "aptos", "near", "polkadot",
        "dot", "cosmos", "avax", "tron", "bsc", "geth", "chia", "monero",
        "xmr", "firedancer", "jito", "raydium", "bot", "trader", "trading",
    },
    # Game servers
    "gaming": {
        "minecraft", "mc", "steam", "csgo", "cs2", "teamspeak", "ts3", "ts",
        "rust", "palworld", "valheim", "terraria", "factorio", "gmod", "ark",
    },
}

_LOOKUP = {name: cat for cat, names in CATEGORIES.items() for name in names}

# "user123", "test01" → same intent as the base word
_TRAILING_DIGITS = re.compile(r"[\d_.-]+$")


def categorize(username: str) -> str:
    u = (username or "").strip().lower()
    if not u or u == "(none)":
        return "other"
    if u in _LOOKUP:
        return _LOOKUP[u]
    base = _TRAILING_DIGITS.sub("", u)
    if base and base in _LOOKUP:
        return _LOOKUP[base]
    return "other"
