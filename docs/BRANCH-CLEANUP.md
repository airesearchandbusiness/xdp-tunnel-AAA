# Stale Feature Branch Cleanup

The feature branches below are fully merged into `main` (verified with
`git merge-base --is-ancestor`). They are retained on the remote for
historical reference only and can be safely deleted at any time.

## Branches scheduled for deletion

| Branch | Head SHA | PR | Status |
|--------|---------:|----|--------|
| `claude/enhance-cicd-testing-CxX0i` | `09fe655` | [#23](https://github.com/airesearchandbusiness/xdp-tunnel-AAA/pull/23) | Merged into `main` |
| `claude/modernize-phase2`           | `11d655f` | [#12](https://github.com/airesearchandbusiness/xdp-tunnel-AAA/pull/12) | Content in `main` |
| `claude/phase3-repair`              | `501bfe8` | [#14](https://github.com/airesearchandbusiness/xdp-tunnel-AAA/pull/14) | Content in `main` |
| `claude/phase4-hardening`           | `e3295ef` | [#15](https://github.com/airesearchandbusiness/xdp-tunnel-AAA/pull/15) | Content in `main` |
| `claude/phase5-makefile`            | `83a29cf` | [#16](https://github.com/airesearchandbusiness/xdp-tunnel-AAA/pull/16) | Content in `main` |
| `claude/refactor-codebase`          | `95452a8` | [#24](https://github.com/airesearchandbusiness/xdp-tunnel-AAA/pull/24) | Content in `main` |
| `claude/review-codebase-apGdE`      | `9183a65` | [#22](https://github.com/airesearchandbusiness/xdp-tunnel-AAA/pull/22) | Content in `main` |
| `claude/refactor-dead-code`         | `6347aa1` |  —  | Content in `main` |

## Verifying before deletion

Before deleting any branch listed above, re-verify it is an ancestor of
`main`:

```bash
git fetch --all
for sha in 09fe655 11d655f 501bfe8 e3295ef 83a29cf 95452a8 9183a65 6347aa1; do
    git merge-base --is-ancestor "$sha" origin/main \
        && echo "$sha: SAFE" || echo "$sha: WARNING"
done
```

All eight SHAs must report `SAFE` before proceeding. Any `WARNING` line
indicates the branch contains commits that are **not** in `main`; cherry-pick
or PR-merge them first.

## Deleting via CLI

Run from a clone with push permission to the real GitHub remote:

```bash
bash scripts/delete-stale-branches.sh
```

The script wraps `git push origin --delete` for each branch and tolerates
already-deleted branches.

## Deleting via the GitHub web UI

1. Open https://github.com/airesearchandbusiness/xdp-tunnel-AAA/branches
2. Locate each branch from the table above in the list
3. Click the trash-can icon at the right edge of the row
4. Confirm

## After deletion

Confirm only `main` remains:

```bash
git ls-remote --heads origin | awk '{print $2}'
# expected: refs/heads/main
```
