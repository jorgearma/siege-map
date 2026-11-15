# Detecciones

Reglas [Sigma](https://sigmahq.io/) escritas a partir de lo que siege-map ve llegar al
servidor. Sigma es un formato neutro: cada regla se convierte a la consulta del SIEM que
uses (Splunk, Elastic, Sentinel…) con `sigma-cli`.

| Regla | Qué detecta | MITRE ATT&CK |
|---|---|---|
| `ssh_username_spray_single_source.yml` | Una IP probando muchos usuarios distintos por SSH (regla base + correlación) | T1110.003 |
| `ssh_legacy_kex_offer.yml` | Clientes SSH que solo ofrecen algoritmos obsoletos (herramientas viejas, malware IoT) | T1595.002 |
| `web_exploit_probe_known_paths.yml` | Peticiones con forma de exploit conocido (PHPUnit, Apache traversal, PHP-CGI…) | T1190 |
| `web_secret_file_hunting.yml` | Búsqueda de `.env`, `.git`, credenciales cloud y claves SSH | T1552.001 |

```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk detections/sigma/web_secret_file_hunting.yml
```

Estado: `experimental`. Se validan en CI con `sigma check detections/sigma` (sintaxis y
validadores de sigma-cli, incluidas las etiquetas ATT&CK). No se han probado contra un SIEM real; los nombres de campo (`src_ip`, `user`, `cs-uri-stem`) dependen de
cómo mapee tu pipeline los logs de sshd y del servidor web.
