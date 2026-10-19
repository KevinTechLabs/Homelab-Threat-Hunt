# Collecting the data

Everything was exported on Oct 18 2026 with the commands below. Raw exports stay off GitHub (see `.gitignore`).

## Wazuh alerts (manager container)

```bash
M=$(docker ps --format '{{.Names}}' | grep -i 'wazuh.manager' | head -1)
docker exec "$M" sh -c 'cd /var/ossec/logs/alerts && tar czf /tmp/wazuh-alerts.tgz alerts.json $(find . -name "ossec-alerts-*.json.gz" -mtime -14)'
docker cp "$M":/tmp/wazuh-alerts.tgz ~/wazuh-alerts.tgz
```

Gotcha: `grep -i manager` alone also matches Prometheus' `alertmanager` container. Match `wazuh.manager`.

## pfSense firewall + Suricata (no SSH needed)

**Diagnostics → Command Prompt → Execute Shell Command:**

```sh
tar czf /tmp/pfsense-logs.tgz /var/log/filter.log* /var/log/suricata/*/alerts.log* /var/log/suricata/*/eve.json* 2>/dev/null
```

Then **Download File** `/tmp/pfsense-logs.tgz` on the same page.

pfSense rotates `filter.log` at 500 KB, which on this network is about 2 days. For longer hunts, rely on the remote syslog copy that Sentinel already receives.

## Pi-hole DNS queries

```bash
sudo pihole-FTL sqlite3 -header -csv /etc/pihole/pihole-FTL.db \
  "SELECT timestamp, type, status, domain, client, reply_type FROM queries WHERE timestamp > strftime('%s','now','-14 days');" \
  | gzip > ~/pihole-queries.csv.gz
```

## Parse

```bash
mkdir -p exports/pfsense exports/wazuh exports/pihole && cp pihole-queries.csv.gz exports/pihole/
tar xzf pfsense-logs.tgz -C exports/pfsense && bunzip2 -k exports/pfsense/var/log/filter.log.*.bz2
tar xzf wazuh-alerts.tgz -C exports/wazuh && find exports/wazuh -name '*.gz' -exec gunzip -k {} \;
python scripts/parse.py exports parsed
```
