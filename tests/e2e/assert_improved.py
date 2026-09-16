"""Fail if the score did not improve, or if any check regressed from pass to fail."""

import json
import sys
from pathlib import Path

before, after = (json.loads(Path(p).read_text()) for p in sys.argv[1:3])
b = {r["check_id"]: r["status"] for r in before["results"]}
a = {r["check_id"]: r["status"] for r in after["results"]}
regressed = [c for c, s in b.items() if s == "pass" and a.get(c) == "fail"]
print(f"score: {before['score']} -> {after['score']}")
if regressed:
    sys.exit(f"regressed: {regressed}")
if after["score"] <= before["score"]:
    sys.exit("score did not improve")
print("OK: the playbook improved the score and broke nothing")
