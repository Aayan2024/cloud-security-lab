# Cloud Security & IAM Exploitation Lab

Matches the "Cloud Security & IAM Exploitation Lab" project on your resume —
built around [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat),
Rhino Security Labs' official open-source "vulnerable by design" AWS
environment generator, plus custom recon and IAM-audit tooling.

## Before you start

- Use a **dedicated AWS account** (a fresh account or an isolated
  sandbox/organization account), never your production account.
- Set an **AWS Budget alert** — CloudGoat provisions real, billable resources.
- Only ever point this at an account **you own**. CloudGoat scenarios are
  meant to be deployed and destroyed by the same person in the same account.
- Always run `deploy-scenario.sh destroy <scenario>` when you're done —
  leftover resources bill silently.

## Layout

```
cloud-lab/
├── setup.sh                      # installs deps, clones CloudGoat
├── scripts/
│   ├── deploy-scenario.sh        # wrapper: create/destroy/list scenarios
│   ├── recon.sh                  # read-only AWS CLI enumeration (IAM + S3)
│   └── iam-privesc-scan.py       # static policy analyzer, flags privesc patterns
└── templates/
    └── remediation-report-template.md
```

## Workflow

```bash
chmod +x setup.sh scripts/*.sh
./setup.sh                                        # clone CloudGoat, install deps
export AWS_PROFILE=cloudgoat                       # dedicated lab profile

./scripts/deploy-scenario.sh list                  # see available scenarios
./scripts/deploy-scenario.sh create iam_privesc_by_rollback

./scripts/recon.sh                                  # enumerate IAM + S3, read-only
python3 scripts/iam-privesc-scan.py recon-output/*/iam-*-policies.txt

# ... work through the scenario manually using the AWS CLI, following
# CloudGoat's own scenario README for the attack narrative ...

./scripts/deploy-scenario.sh destroy iam_privesc_by_rollback
```

## What each piece does

- **setup.sh** — installs prerequisites and clones the official CloudGoat
  repo (the vulnerable infrastructure itself is Rhino Security Labs' code,
  not reproduced here).
- **recon.sh** — read-only enumeration only (`list-*`, `get-*`,
  `describe-*` calls). Dumps IAM users/roles/policies and S3 bucket exposure
  to timestamped JSON/text files for your report.
- **iam-privesc-scan.py** — a small static analyzer that checks exported
  policy documents against publicly documented IAM privilege-escalation
  patterns (PassRole+RunInstances, CreatePolicyVersion, etc. — the same
  catalogue Rhino Security Labs themselves published). It's a detection
  tool: it flags risk, it doesn't perform the escalation.
- **templates/remediation-report-template.md** — the report structure
  referenced on your resume ("comprehensive remediation reports focusing
  on Least Privilege access, IAM policy hardening").

## On the actual attack steps

CloudGoat scenarios ship with their own official README per scenario
(inside `cloudgoat/scenarios/<name>/cloudgoat.md`) that walks through the
intended attack path using plain AWS CLI commands — that's the standard
way people work through them, and it's worth doing manually rather than
scripting end-to-end, since the point of the exercise is learning to read
IAM policy documents and spot the escalation path yourself. Use
`iam-privesc-scan.py` to check your own findings against the pattern
catalogue once you think you've spotted it.

## Teardown

```bash
./scripts/deploy-scenario.sh destroy <scenario_name>
```

Then double check the AWS console (IAM, S3, EC2, Lambda) for anything
CloudGoat's own destroy step might have missed.
