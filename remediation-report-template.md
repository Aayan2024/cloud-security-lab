# Cloud Security Assessment — Remediation Report

**Target account:** <AWS account ID / alias>
**Scenario:** <CloudGoat scenario name>
**Assessor:** Aayan Hasan
**Date:** <date>

---

## 1. Executive Summary

<2-3 sentence plain-language summary: what was tested, what was found,
overall risk level.>

## 2. Scope

- AWS account: <account id>
- Services in scope: IAM, S3, EC2, Lambda (adjust per scenario)
- Method: CloudGoat-deployed scenario, read-only recon via `recon.sh`,
  static policy analysis via `iam-privesc-scan.py`, manual verification

## 3. Findings

| # | Finding | Severity | Affected Resource | Pattern |
|---|---------|----------|--------------------|---------|
| 1 | | Critical / High / Medium / Low | | e.g. PassRole+EC2RunInstances |
| 2 | | | | |

### Finding 1 — <title>

**Description:** <what the misconfiguration is>

**Evidence:** <reference to recon-output/ file or scan output>

**Impact:** <what an attacker could do with it>

**Remediation:**
- <specific least-privilege policy change>
- <e.g. scope Resource to specific ARN instead of "*">
- <e.g. add a Condition requiring MFA / source IP>

---

## 4. Overexposed S3 Buckets

| Bucket | Public Access Block | Bucket Policy | Recommendation |
|--------|---------------------|----------------|-----------------|
| | | | |

## 5. IAM Privilege Escalation Paths

<Summarize output from iam-privesc-scan.py — which principals have which
risky action combinations, and the least-privilege fix for each.>

## 6. General Recommendations

- Enforce least privilege on all IAM policies; replace `"Resource": "*"`
  with explicit ARNs wherever possible.
- Enable S3 Block Public Access at the account level unless a bucket has
  a documented business need to be public.
- Require MFA for any IAM action that modifies IAM policies or roles.
- Enable CloudTrail + GuardDuty if not already active, so these paths are
  detectable in production.

## 7. Appendix

- Raw recon output: `recon-output/<timestamp>/`
- Scan output: `iam-privesc-scan.py` results (attach or link)
