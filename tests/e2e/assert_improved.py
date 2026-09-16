"""Compare two JSON reports and fail if the remediation did not help.

Usage: assert_improved.py before.json after.json [--expect-higher-score]

The score alone is not always the right assertion: a failing critical check caps
it at 49, so a container with an extra UID 0 account stays at 49 no matter how
much else was fixed. The default assertion is therefore "fewer failures and no
regressions", and --expect-higher-score is used for the phase where the manual
step has been done too.
"""

import json
import sys
from pathlib import Path


def load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def failing(report: dict) -> set[str]:
    return {r["check_id"] for r in report["results"] if r["status"] == "fail"}


def main(argv: list[str]) -> int:
    before, after = load(argv[1]), load(argv[2])
    expect_higher_score = "--expect-higher-score" in argv[3:]

    before_failing, after_failing = failing(before), failing(after)
    fixed = sorted(before_failing - after_failing)
    regressed = sorted(after_failing - before_failing)

    print(f"score:    {before['score']} -> {after['score']}")
    print(f"failures: {len(before_failing)} -> {len(after_failing)}")
    print(f"fixed:    {', '.join(fixed) or 'nothing'}")

    if regressed:
        return f"checks that now fail and did not before: {regressed}"
    if not fixed:
        return "the remediation fixed nothing"
    if after["score"] < before["score"]:
        return f"the score dropped: {before['score']} -> {after['score']}"
    if expect_higher_score and after["score"] <= before["score"]:
        return f"the score did not improve: {before['score']} -> {after['score']}"

    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
