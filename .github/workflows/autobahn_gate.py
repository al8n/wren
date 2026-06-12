#!/usr/bin/env python3
"""Gate the Autobahn TestSuite reports: fail on any case marked FAILED.

Autobahn records a `behavior` (and `behaviorClose`) verdict per case in
`<reports>/{servers,clients}/index.json`. The acceptable verdicts are:

    OK             — fully conformant
    NON-STRICT     — conformant under a permitted, non-strict reading
    INFORMATIONAL  — observational case, no pass/fail
    UNIMPLEMENTED  — case the peer opted out of

Anything else (notably FAILED, and the never-expected MISSING / "WRONG CODE")
fails the gate. Usage: autobahn_gate.py <reports-dir>
"""

import json
import sys
from pathlib import Path

PASS = {"OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED"}


def case_sort_key(case_id: str):
    parts = []
    for p in case_id.split("."):
        try:
            parts.append((0, int(p)))
        except ValueError:
            parts.append((1, p))
    return parts


def check_index(index_path: Path) -> list[str]:
    """Return a list of failure descriptions for one index.json."""
    failures = []
    data = json.loads(index_path.read_text())
    for agent, cases in data.items():
        for case_id, result in sorted(cases.items(), key=lambda kv: case_sort_key(kv[0])):
            behavior = result.get("behavior", "MISSING")
            behavior_close = result.get("behaviorClose", "MISSING")
            if behavior not in PASS or behavior_close not in PASS:
                failures.append(
                    f"{index_path.parent.name}/{agent} case {case_id}: "
                    f"behavior={behavior} behaviorClose={behavior_close}"
                )
    return failures


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: autobahn_gate.py <reports-dir>", file=sys.stderr)
        return 2
    reports = Path(sys.argv[1])

    indexes = sorted(reports.glob("*/index.json"))
    if not indexes:
        print(f"no index.json under {reports}/ — did the suite run?", file=sys.stderr)
        return 2

    all_failures: list[str] = []
    total = 0
    for index in indexes:
        data = json.loads(index.read_text())
        total += sum(len(cases) for cases in data.values())
        all_failures.extend(check_index(index))

    print(f"Evaluated {total} Autobahn cases across {len(indexes)} report set(s).")
    if all_failures:
        print(f"\n{len(all_failures)} FAILED case(s):")
        for f in all_failures:
            print(f"  - {f}")
        return 1
    print("All cases passed (OK / NON-STRICT / INFORMATIONAL / UNIMPLEMENTED).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
