#!/usr/bin/env python3
"""Append a Markdown summary of JUnit test results to GITHUB_STEP_SUMMARY.

Usage: junit-summary.py <path-to-junit.xml> [<heading>]

Designed for GitHub Actions. Silently no-ops when the file is missing so it
can be wired with `if: always()` without exploding when an earlier step has
failed before producing any XML.
"""
import os
import sys
import xml.etree.ElementTree as ET


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: junit-summary.py <junit.xml> [heading]", file=sys.stderr)
        return 2

    xml_path = sys.argv[1]
    heading = sys.argv[2] if len(sys.argv) > 2 else "Unit Test Results"

    if not os.path.isfile(xml_path):
        # Step likely ran with no test output — silently skip.
        return 0

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"junit-summary: failed to parse {xml_path}: {e}", file=sys.stderr)
        return 0

    root = tree.getroot()
    # CTest emits <testsuites> with one <testsuite> child; some emitters skip
    # the wrapper and use <testsuite> as root. Handle both cases.
    ts = root.find("testsuite") if root.tag == "testsuites" else root
    if ts is None:
        return 0

    tests = int(ts.get("tests", 0))
    failures = int(ts.get("failures", 0))
    errors = int(ts.get("errors", 0))
    skipped = int(ts.get("skipped", 0))
    passed = tests - failures - errors - skipped
    status = ":white_check_mark:" if failures + errors == 0 else ":x:"

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        # Local invocation — print to stdout instead.
        print(f"{status} {heading}: {passed}/{tests} passed "
              f"({failures + errors} failed, {skipped} skipped)")
        return 0

    with open(summary_path, "a") as f:
        f.write(f"## {status} {heading}\n\n")
        f.write("| Metric  | Count |\n|---------|-------|\n")
        f.write(f"| Passed  | {passed} |\n")
        f.write(f"| Failed  | {failures + errors} |\n")
        f.write(f"| Skipped | {skipped} |\n")
        f.write(f"| **Total** | **{tests}** |\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
