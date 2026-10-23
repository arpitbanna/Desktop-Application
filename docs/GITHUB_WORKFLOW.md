# TrustRoot Mobile: GitHub Contribution & Release Workflow

## 1. Overview
This guide defines the engineering standard for version control, code review, automated verification, and safe GitHub synchronization for **TrustRoot Mobile**.

---

## 2. Mandatory Pre-Commit Checklist
Before staging or committing any changes:

1. **Clean Workspace & No Secrets**:
   - Ensure no `.env`, local signing keys (`.keystore`, `.jks`), or raw private keys are present.
   - Run `git status` to verify `.gitignore` excludes `node_modules/`, `coverage/`, `build/`, and local files.
2. **Type Safety Verification**:
   ```bash
   npm run typecheck
   ```
   Must exit with code 0 (zero TypeScript errors).
3. **Automated Security & Unit Tests**:
   ```bash
   npm test
   ```
   Must pass 100% of the test suite (all 23 tests).
4. **Swift / Native Syntax Validation (if native files modified)**:
   ```bash
   swiftc -parse ios/TrustRoot/Security/*.swift
   ```

---

## 3. Conventional Commit Standard
Use conventional commits to maintain clear audit history:

- `feat:` New capability or feature (e.g. `feat: add hardware key attestation inspection`)
- `fix:` Bug fix or cryptographic adjustment (e.g. `fix: validate RSA-OAEP parameter specification`)
- `test:` Adding or refining test suites (e.g. `test: add ciphertext bit-flipping tamper tests`)
- `docs:` Documentation updates (e.g. `docs: update platform limitations matrix`)
- `chore:` Dependency, build configuration, or CI changes (e.g. `chore: configure CI workflow`)

---

## 4. Step-by-Step Commit & Push Workflow

```bash
# 1. Review changed files
git status

# 2. Inspect exact diffs
git diff

# 3. Stage only intentional files
git add <files>

# 4. Commit with descriptive message
git commit -m "feat(security): implement offline hybrid encryption pipeline"

# 5. Fetch remote to ensure no upstream divergence
git fetch origin main

# 6. Push to remote main
git push origin main

# 7. Confirm remote commit
git log -1 --stat
```

---

## 5. Continuous Integration (GitHub Actions)
The repository includes `.github/workflows/ci.yml` which executes on every push and pull request to `main`:
- Checks out code with full history.
- Sets up Node.js runtime.
- Installs dependencies using clean package resolution.
- Executes `npm run typecheck` (Static analysis).
- Runs `npm test` with code coverage analysis.

> **Honest CI Notice**: GitHub-hosted Linux runners test the authentic software cryptographic simulator and package integrity. Testing physical Android StrongBox Keymaster chips (Titan M2 / Knox Vault) or Apple Secure Enclave coprocessors requires a physically connected hardware test runner.
