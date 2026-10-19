#!/usr/bin/env python3
"""Fail if any Wazuh custom rule ID is defined more than once.

Wazuh accepts a duplicate rule ID with only a warning in ossec.log, and one of the
two rules silently stops doing its job. Run this against every rule file you
deploy (or straight against the manager's rules directory):

    python scripts/check_rule_ids.py detections/wazuh/*.xml
    docker exec single-node-wazuh.manager-1 sh -c 'cat /var/ossec/etc/rules/*.xml' > /tmp/all.xml
    python scripts/check_rule_ids.py /tmp/all.xml

Exit code 0 = clean, 1 = duplicates or IDs outside the custom range (100000-120000).
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

RULE = re.compile(r'<rule\b[^>]*\bid="(\d+)"')
COMMENT = re.compile(r"<!--.*?-->", re.S)


def scan(paths):
    seen = defaultdict(list)
    for path in paths:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        # blank out comments but keep line numbers
        text = COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
        for m in RULE.finditer(text):
            seen[int(m.group(1))].append(f"{path}:{text.count(chr(10), 0, m.start()) + 1}")
    return seen


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    seen = scan(argv)
    problems = 0
    for rid, where in sorted(seen.items()):
        if len(where) > 1:
            problems += 1
            print(f"DUPLICATE rule id {rid}: " + ", ".join(where))
        if not 100000 <= rid <= 120000:
            problems += 1
            print(f"OUT OF RANGE rule id {rid} (custom rules use 100000-120000): {where[0]}")
    print(f"{len(seen)} rule IDs checked, {problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
