import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
CHECK = [sys.executable, str(ROOT / "scripts" / "check_rule_ids.py")]


def run(*files):
    return subprocess.run(CHECK + [str(f) for f in files], capture_output=True, text=True)


def test_the_collision_found_in_this_hunt_is_caught():
    r = run(FIX / "purple_team_excerpt.xml", FIX / "vaultwarden_excerpt.xml")
    assert r.returncode == 1
    for rid in ("100201", "100202", "100220"):
        assert f"DUPLICATE rule id {rid}" in r.stdout
    assert "DUPLICATE rule id 100213" not in r.stdout


def test_ids_inside_comments_are_ignored():
    r = run(FIX / "vaultwarden_excerpt.xml")
    assert r.returncode == 0, r.stdout


def test_shipped_detections_are_clean():
    r = run(*sorted((ROOT / "detections" / "wazuh").glob("*.xml")))
    assert r.returncode == 0, r.stdout
