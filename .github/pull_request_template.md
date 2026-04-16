## Summary

<!-- What does this PR do? Link the related issue if applicable (Fixes #123). -->

## Type of change

- [ ] Bug fix
- [ ] New feature / enhancement
- [ ] Refactor (no behaviour change)
- [ ] CI / tooling change
- [ ] Documentation
- [ ] Security fix

## Pre-merge checklist

### Required
- [ ] `make test-unit` passes locally (186+ tests)
- [ ] `make format` was run (or `make format-check` is clean)
- [ ] `make lint` passes (clang-format, cppcheck, shellcheck)
- [ ] CI is green: lint · build · build/gcc · build/clang-18 · test/unit

### Wire-format changes (if `common.h` was modified)
- [ ] Struct changes mirrored in `loader/tachyon.h`
- [ ] Struct changes mirrored in `kmod/mod.c`
- [ ] Sizes verified with `static_assert` or manual check

### Crypto changes (if `loader/crypto.cpp` was modified)
- [ ] New test cases added to `tests/unit/test_crypto.cpp`
- [ ] No real keys, IVs, or secrets committed (use deterministic test vectors)
- [ ] `make test-sanitize` clean (ASan + UBSan)

### Security-sensitive changes
- [ ] Reviewed the [SECURITY.md](../SECURITY.md) threat model
- [ ] No new external dependencies without a corresponding vulnerability scan
