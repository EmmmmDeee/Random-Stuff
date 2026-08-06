# Security Policy & Hardening Guide

**Last Updated**: 2026-08-06  
**Status**: Active

---

## Overview

This repository contains educational research materials on payment fraud and security analysis. This security policy documents:
- Access control procedures
- Branch protection rules
- Incident response procedures
- Threat hunting checklists
- Verification procedures

---

## 1. Repository Access Control

### Branch Protection Rules

**Protected Branches**: `main`

#### Requirements for Merge to Main

- [x] Require pull request reviews before merging
- [x] Require code reviews: 1 approval minimum
- [x] Dismiss stale pull request approvals when new commits are pushed
- [x] Require status checks to pass before merging
- [x] Require branches to be up to date before merging
- [x] Require commit signatures
- [x] Require conversation resolution before merging
- [x] Allow force pushes: NO
- [x] Allow deletions: NO

#### Enforcement

- Branch protection is **mandatory** for `main`
- Only GitHub organization admins can bypass these rules
- All changes must go through pull request process
- No direct pushes to `main`

---

## 2. Authentication & Credentials

### Personal Access Tokens

**Policy**: 
- No personal access tokens should be created for repository access
- If tokens are created, they must be:
  - [ ] Scoped to minimum necessary permissions (read-only when possible)
  - [ ] Set to expire within 30 days
  - [ ] Monitored for unauthorized creation
  - [ ] Immediately revoked if compromised

**Verification**:
```bash
# Check for any suspicious tokens
git log -p --all | grep -i "github_pat\|ghp_\|gho_"
```

### SSH Keys

**Policy**:
- Use SSH keys with passphrases for local development
- Do not store SSH private keys in repositories
- Add SSH keys to `.gitignore`:
  ```
  # .gitignore
  *.pem
  *.key
  id_rsa*
  ```

### Two-Factor Authentication (2FA)

**Requirement**: All maintainers MUST enable 2FA

**Recommended**: Hardware security key (U2F/WebAuthn)
- Phishing-resistant (unlike SMS)
- Works across GitHub and development tools
- Examples: YubiKey, Titan, Nitrokey

---

## 3. Branch Management

### Current Branch Structure

```
main (DEFAULT)
├── Status: Production-ready, cleaned code
├── Protection: Enabled (PR + review required)
├── Contains: Fraud Bible files + supporting tools
└── IoC content: REMOVED

claude/focused-brown-CczCb (LEGACY)
├── Status: Deprecated, do not use
├── Contains: Full IoC infrastructure (iocs.csv, scanner)
├── Action: To be deleted after validation
└── Note: Do not clone or reference this branch
```

### New Branch Policy

**For Feature Development**:
```bash
git checkout -b feature/description
# Make changes
git push -u origin feature/description
# Create pull request on GitHub
```

**Branch naming convention**:
- `feature/` - New functionality
- `fix/` - Bug fixes
- `security/` - Security hardening
- `docs/` - Documentation updates

**Deletion Policy**:
- Delete merged branches immediately
- Keep main branch clean (no stale branches)
- Archive important historical branches with git tag

---

## 4. Commit Signing

### GPG Signing Requirement

All commits to `main` MUST be GPG-signed.

**Setup**:
```bash
# Generate GPG key
gpg --full-generate-key
# (RSA, 4096 bits, expiration: 1 year recommended)

# Get key ID
gpg --list-secret-keys --keyid-format long
# Copy the key ID (16 characters after "sec   rsa4096/")

# Configure git
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true

# Add public key to GitHub
# https://github.com/settings/keys
gpg --armor --export <KEY_ID>
# Copy output to GitHub → SSH and GPG keys → New GPG key
```

**Verification**:
```bash
# Check if commits are signed
git log --show-signature --oneline -10

# Should show: gpg: Good signature from "Your Name <email>"
```

---

## 5. Threat Hunting & Monitoring

### Daily Security Checks

Run these checks daily to detect compromise:

```bash
#!/bin/bash
# daily_security_check.sh

echo "=== Repository Security Check ===" 
date

# Check 1: Credential exposure
echo "Checking for exposed credentials..."
git log -p --all | grep -i "password\|token\|secret\|api_key" && \
  echo "⚠️  WARNING: Potential credential exposure detected" || \
  echo "✅ No credentials found in git history"

# Check 2: Unsigned commits on main
echo "Checking commit signatures..."
git log --oneline main | while read commit msg; do
  git show --quiet --format='%G?' $commit | grep -q "G" || \
    echo "⚠️  WARNING: Unsigned commit detected: $commit"
done

# Check 3: Unauthorized users
echo "Checking for unexpected commits..."
git log --oneline --all | head -20

# Check 4: Branch integrity
echo "Checking branch status..."
git branch -v

echo "=== Check Complete ===" 
```

### Weekly Mirror Check

Verify no unauthorized copies exist:

```bash
# Search GitHub for copies
# https://github.com/search?q=Random-Stuff+fork:true

# Verify canonical source
git remote -v
# Should show: origin	https://github.com/EmmmmDeee/Random-Stuff.git

# Compare branches with remote
git fetch origin
git diff main origin/main
# Should show no differences
```

### Monthly Access Audit

- [ ] Review GitHub collaborators (Settings → Collaborators)
- [ ] Check for unexpected SSH keys (Settings → SSH and GPG keys)
- [ ] Audit personal access tokens (Settings → Developer settings → Tokens)
- [ ] Verify branch protection rules are still enabled
- [ ] Check git log for suspicious activity

---

## 6. Incident Response

### If Credentials Are Exposed

1. **Immediate** (next 5 minutes):
   - Revoke exposed credentials
   - Force password reset on GitHub
   - Rotate all API tokens

2. **Urgent** (next 30 minutes):
   - Check git log for unauthorized commits
   - Audit account activity (GitHub login history)
   - Re-enable 2FA with hardware key

3. **Investigation** (next 4 hours):
   - Preserve evidence (export git history)
   - Contact GitHub Security Team
   - File incident report
   - Update security procedures

### If Malicious Commit Is Detected

1. **Immediate**:
   ```bash
   git revert <malicious-commit-hash>
   git push origin main
   ```

2. **Urgent**:
   - Force all users to pull latest version
   - Revoke all access tokens/SSH keys
   - Re-enable all branch protection rules

3. **Investigation**:
   - Analyze commit metadata (author, timestamp, IP)
   - Check for backdoors or persistence mechanisms
   - Audit all changes between last known-good commit and malicious commit

### If Repository Is Forked Maliciously

1. **Immediate**:
   - Document fork details (URL, last commit, file changes)
   - Report to GitHub Abuse Team
   - Notify users of official vs. malicious copy

2. **Urgent**:
   - Add notice to README: "Official repository: https://github.com/EmmmmDeee/Random-Stuff"
   - Pin this notice in GitHub Discussions/Issues

3. **Investigation**:
   - Compare malicious fork content with canonical
   - Identify what was added/modified
   - Track if users cloned malicious version

---

## 7. Development Workflow

### Creating a Pull Request

1. Create feature branch from `main`:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/my-feature
   ```

2. Make changes:
   ```bash
   # Edit files
   git add <files>
   git commit -S -m "Descriptive commit message"
   # -S flag signs the commit
   ```

3. Push to GitHub:
   ```bash
   git push -u origin feature/my-feature
   ```

4. Create PR on GitHub:
   - Title: Clear, descriptive
   - Description: Why this change? What does it do?
   - Link related issues
   - Request reviewers

5. Code review:
   - Address feedback
   - Push new commits to same branch
   - Request re-review

6. Merge:
   - Squash or rebase (keep history clean)
   - Delete feature branch after merge

---

## 8. Visibility & Transparency

### What to Communicate

- [ ] Security updates (new protection rules, policy changes)
- [ ] Incident reports (compromises, attacks, breaches)
- [ ] Access changes (new maintainers, revoked access)
- [ ] Dependency vulnerabilities (updates to prevent exploitation)

### What to Redact

- [ ] Personal information (emails, phone numbers, addresses)
- [ ] Authentication tokens or credentials
- [ ] Internal security procedures
- [ ] Specific vulnerability details (before public disclosure)

---

## 9. External Security Review

This repository conducts regular security testing:

### Automated Testing
- Daily threat hunting (credential exposure, unauthorized commits)
- Weekly mirror consistency checks
- Monthly access audits

### Manual Testing
- Quarterly penetration testing (red team exercises)
- Annual comprehensive security audit
- Ad-hoc threat hunting as needed

### Public Disclosure
- Vulnerabilities reported via responsible disclosure
- SECURITY.md documents how to report issues
- Updates communicated transparently

---

## 10. References

- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
- [Git Security](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
- [OWASP Repository Security](https://owasp.org/www-community/Repository_Security)
- [GPG Key Generation](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key)

---

**Last Review**: 2026-08-06  
**Next Review**: 2026-09-06 (monthly)

