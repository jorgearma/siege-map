"""
What are the HTTP bots looking for?

Maps a probed URI to the product/vulnerability the request is known to
target. Matching is done on the full request URI (path + query string).
First match wins, so specific exploits go before generic product probes.

A match means "this request has the shape of a probe for X", not that the
server is vulnerable.
"""
import re
from typing import NamedTuple, Optional


class Signature(NamedTuple):
    id: str          # CVE id when there is one, otherwise a short slug
    name: str
    product: str
    kind: str        # exploit | exposure | recon | c2


def _sig(pattern: str, id: str, name: str, product: str, kind: str = "exploit"):
    return re.compile(pattern, re.I), Signature(id, name, product, kind)


SIGNATURES = [
    # ── Specific exploits ─────────────────────────────────────
    _sig(r"/phpunit/.*eval-stdin\.php", "CVE-2017-9841", "PHPUnit eval-stdin RCE", "PHPUnit"),
    _sig(r"/cgi-bin/luci/;stok=/locale", "CVE-2023-1389", "TP-Link Archer command injection", "TP-Link"),
    _sig(r"/GponForm/diag_Form", "CVE-2018-10561", "GPON router auth bypass / RCE", "GPON router"),
    _sig(r"/HNAP1", "CVE-2015-2051", "D-Link HNAP command injection", "D-Link"),
    _sig(r"/actuator/gateway/routes", "CVE-2022-22947", "Spring Cloud Gateway code injection", "Spring"),
    _sig(r"/_ignition/execute-solution", "CVE-2021-3129", "Laravel Ignition RCE", "Laravel"),
    _sig(r"/cgi-bin/(?:\.%2e|%2e%2e|\.\.)/", "CVE-2021-41773", "Apache 2.4.49 path traversal", "Apache httpd"),
    _sig(r"%ADd\+allow_url_include|php-cgi\.exe", "CVE-2024-4577", "PHP-CGI argument injection (Windows)", "PHP"),
    _sig(r"\?-d\+allow_url_include|\?%2dd\+allow_url_include", "CVE-2012-1823", "PHP-CGI argument injection", "PHP"),
    _sig(r"/remote/fgt_lang\?lang=.*\.\./", "CVE-2018-13379", "FortiOS SSL VPN path traversal", "Fortinet"),
    _sig(r"/dana-na/\.\./dana/html5acc", "CVE-2019-11510", "Pulse Secure arbitrary file read", "Pulse Secure"),
    _sig(r"/api/v1/totp/user-backup-code", "CVE-2023-46805", "Ivanti Connect Secure auth bypass", "Ivanti"),
    _sig(r"/ssl-vpn/hipreport\.esp", "CVE-2024-3400", "PAN-OS GlobalProtect command injection", "Palo Alto"),
    _sig(r"/console/css/%252e%252e%252fconsole\.portal", "CVE-2020-14882", "WebLogic console RCE", "WebLogic"),
    _sig(r"/tmui/login\.jsp/\.\.;/", "CVE-2020-5902", "F5 BIG-IP TMUI RCE", "F5 BIG-IP"),
    _sig(r"/mgmt/tm/util/bash", "CVE-2022-1388", "F5 BIG-IP iControl REST auth bypass", "F5 BIG-IP"),
    _sig(r"/vpn/\.\./vpns/", "CVE-2019-19781", "Citrix ADC path traversal", "Citrix"),
    _sig(r"/ctrlt/DeviceUpgrade_1", "CVE-2017-17215", "Huawei HG532 RCE (Mirai)", "Huawei"),
    _sig(r"/picsdesc\.xml|/UD/act\?1", "CVE-2014-8361", "Realtek SDK miniigd RCE (Mirai)", "Realtek"),
    _sig(r"/api/jsonws/invoke", "CVE-2020-7961", "Liferay JSON deserialization", "Liferay"),
    _sig(r"/autodiscover/autodiscover\.json.*@", "CVE-2021-34473", "Exchange ProxyShell", "Exchange"),
    _sig(r"/device\.rsp\?opt=sys&cmd=", "CVE-2024-3721", "TBK DVR command injection", "TBK DVR"),
    _sig(r"/geoserver/(?:wfs|ows|wms)", "CVE-2024-36401", "GeoServer OGC eval injection", "GeoServer"),
    _sig(r"/setup\.cgi\?next_file=netgear\.cfg", "netgear-setup-rce", "Netgear DGN setup.cgi RCE (Mirai)", "Netgear"),
    _sig(r"/shell\?cd\+/tmp", "jaws-shell-rce", "JAWS web server shell RCE (Mirai)", "DVR"),
    _sig(r"/boaform/admin/formLogin", "boa-router-login", "Boa/Netlink router login brute force", "GPON router", "recon"),

    # ── C2 / tooling ──────────────────────────────────────────
    _sig(r"^/(?:aaa9|aab8|aab9|ab2g|ab2h)$", "cobaltstrike-stager", "Cobalt Strike stager checksum probe", "Cobalt Strike", "c2"),
    _sig(r"/nmaplowercheck|/evox/about|^/sdk$", "nmap-nse", "Nmap NSE HTTP script", "Nmap", "recon"),

    # ── Exposed secrets and metadata ──────────────────────────
    _sig(r"/\.git/(?:config|HEAD|index)", "git-exposure", "Exposed .git repository", "Git", "exposure"),
    _sig(r"/\.env(?:\.|$|\?)", "dotenv-exposure", "Exposed .env file", "dotenv", "exposure"),
    _sig(r"/\.aws/credentials", "aws-credentials", "Exposed AWS credentials file", "AWS", "exposure"),
    _sig(r"/\.ssh/|id_rsa|authorized_keys", "ssh-keys", "Exposed SSH keys", "SSH", "exposure"),
    _sig(r"/\.DS_Store", "ds-store", "Exposed .DS_Store listing", "macOS", "exposure"),
    _sig(r"/(?:phpinfo|info)\.php", "phpinfo", "phpinfo() disclosure", "PHP", "exposure"),
    _sig(r"/server-status", "apache-status", "Apache mod_status exposure", "Apache httpd", "exposure"),
    _sig(r"/actuator(?:/|$)", "spring-actuator", "Spring Boot Actuator exposure", "Spring", "exposure"),
    _sig(r"/telescope/requests", "laravel-telescope", "Laravel Telescope exposure", "Laravel", "exposure"),
    _sig(r"/wp-json/wp/v2/users", "wp-user-enum", "WordPress user enumeration", "WordPress", "recon"),
    _sig(r"/config\.json|/credentials\.json|/secrets\.(?:json|ya?ml)", "config-exposure", "Exposed config / credentials file", "Generic", "exposure"),
    _sig(r"\.(?:sql|bak|tar\.gz|zip)(?:\?|$)", "backup-exposure", "Backup / dump file hunting", "Generic", "exposure"),

    # ── Product discovery ─────────────────────────────────────
    _sig(r"/wp-content/plugins/", "wp-plugin", "WordPress plugin probe", "WordPress", "recon"),
    _sig(r"/wp-login\.php|/wp-admin|/xmlrpc\.php", "wordpress-login", "WordPress login / XML-RPC", "WordPress", "recon"),
    _sig(r"phpmyadmin|/pma/|adminer\.php", "db-admin-panel", "Database admin panel", "phpMyAdmin", "recon"),
    _sig(r"/remote/(?:logincheck|login)", "fortigate-vpn", "FortiGate SSL VPN portal", "Fortinet", "recon"),
    _sig(r"/global-protect/login\.esp", "globalprotect", "GlobalProtect portal", "Palo Alto", "recon"),
    _sig(r"/dana-na/", "pulse-vpn", "Pulse / Ivanti VPN portal", "Ivanti", "recon"),
    _sig(r"/owa/|/ecp/|/autodiscover/", "exchange", "Exchange / OWA discovery", "Exchange", "recon"),
    _sig(r"/manager/html", "tomcat-manager", "Tomcat manager", "Tomcat", "recon"),
    _sig(r"/solr/", "solr", "Apache Solr admin", "Solr", "recon"),
    _sig(r"/druid/", "druid", "Apache Druid console", "Druid", "recon"),
    _sig(r"/jenkins/|/script$", "jenkins", "Jenkins console", "Jenkins", "recon"),
    _sig(r"/console/login/LoginForm\.jsp", "weblogic-console", "WebLogic console", "WebLogic", "recon"),
    _sig(r"/cgi-bin/luci", "openwrt-luci", "OpenWrt LuCI login", "OpenWrt", "recon"),
    _sig(r"/login\.rsp", "dvr-login", "DVR login page", "DVR", "recon"),
    _sig(r"\.action(?:\?|$)|/struts", "struts", "Apache Struts endpoint", "Struts", "recon"),
    _sig(r"/v2/_catalog", "docker-registry", "Docker registry catalog", "Docker", "recon"),
    _sig(r"/api/v1/(?:pods|namespaces)|/version$", "kubernetes-api", "Kubernetes API", "Kubernetes", "recon"),
    _sig(r"shell\.php|cmd\.php|webshell|c99\.php|r57\.php|alfa\.php|wso\.php", "webshell-hunt", "Looking for someone else's web shell", "Web shell", "recon"),
]


def match_signature(uri: str) -> Optional[Signature]:
    if not uri:
        return None
    for regex, sig in SIGNATURES:
        if regex.search(uri):
            return sig
    return None
