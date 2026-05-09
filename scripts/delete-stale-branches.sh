#!/usr/bin/env bash
#
# Delete the stale `claude/*` feature branches from the remote.
#
# All branches in the list below are fully merged into `main` — see
# docs/BRANCH-CLEANUP.md for the verification table and SHA list.
#
# Run from a clone with push permission. The script tolerates branches
# that are already gone (some hosts block direct deletion via push, in
# which case use the GitHub web UI — see docs/BRANCH-CLEANUP.md).

set -u

BRANCHES=(
    claude/enhance-cicd-testing-CxX0i
    claude/modernize-phase2
    claude/phase3-repair
    claude/phase4-hardening
    claude/phase5-makefile
    claude/refactor-codebase
    claude/review-codebase-apGdE
    claude/refactor-dead-code
)

echo "Deleting ${#BRANCHES[@]} stale branches from origin..."
echo

failures=0
for b in "${BRANCHES[@]}"; do
    printf '  %-40s ' "$b"
    if git push origin --delete "$b" >/dev/null 2>&1; then
        echo "deleted"
    else
        echo "skipped (already gone or no permission)"
        failures=$((failures + 1))
    fi
done

echo
if [ "$failures" -eq 0 ]; then
    echo "All branches deleted."
else
    echo "$failures branch(es) could not be deleted via CLI."
    echo "See docs/BRANCH-CLEANUP.md for the web-UI alternative."
fi
