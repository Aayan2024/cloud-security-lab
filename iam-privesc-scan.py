#!/usr/bin/env python3
"""
iam-privesc-scan.py

Static audit tool: reads IAM policy JSON documents and flags permission
combinations that match publicly documented AWS IAM privilege-escalation
patterns (the same methodology used by open-source tools like Cloudsplaining
and PMapper, originally catalogued in Rhino Security Labs' public research).

This is a DETECTION tool — it flags risk, it does not exploit anything.
Point it at exported policy JSON (e.g. from `aws iam get-policy-version`
or the output of recon.sh) to get a quick risk summary for your report.

Usage:
    python3 iam-privesc-scan.py policy1.json policy2.json ...
    python3 iam-privesc-scan.py recon-output/*/policy-docs/*.json
"""

import json
import sys
from pathlib import Path

# Each entry: (finding name, set of actions that together indicate the risk,
# short description). Matches if the policy grants ALL actions in the set
# (case-insensitive, wildcard-aware) on a resource of "*" or unrestricted scope.
PRIVESC_PATTERNS = [
    ("CreatePolicyVersion",
     {"iam:createpolicyversion"},
     "Can create a new default policy version -> attach an admin policy version to self"),
    ("SetDefaultPolicyVersion",
     {"iam:setdefaultpolicyversion"},
     "Can roll back to a previously permissive policy version"),
    ("AttachUserPolicy",
     {"iam:attachuserpolicy"},
     "Can attach AdministratorAccess (or any managed policy) directly to self"),
    ("AttachRolePolicy+PassRole",
     {"iam:attachrolepolicy", "iam:passrole"},
     "Can attach a privileged policy to a role, then pass that role to a service"),
    ("PutUserPolicy",
     {"iam:putuserpolicy"},
     "Can write an inline admin policy directly onto self"),
    ("CreateAccessKey",
     {"iam:createaccesskey"},
     "Can mint new access keys for another (possibly higher-privileged) user"),
    ("PassRole+EC2RunInstances",
     {"iam:passrole", "ec2:runinstances"},
     "Can launch an EC2 instance with an attached privileged instance role"),
    ("PassRole+LambdaCreate",
     {"iam:passrole", "lambda:createfunction", "lambda:invokefunction"},
     "Can create and invoke a Lambda function running as a privileged role"),
    ("PassRole+CloudFormation",
     {"iam:passrole", "cloudformation:createstack"},
     "Can deploy a CloudFormation stack that provisions resources under a privileged role"),
    ("UpdateAssumeRolePolicy",
     {"iam:updateassumerolepolicy"},
     "Can modify a role's trust policy to allow itself to assume it"),
]


def normalize(value):
    """IAM Action/Resource fields can be a string or a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def collect_actions(policy_doc):
    """Return the set of lower-cased actions granted by Allow statements."""
    actions = set()
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        for action in normalize(stmt.get("Action")):
            actions.add(action.lower())
    return actions


def action_matches(granted_actions, required_action):
    """Handle exact matches and simple wildcard actions like iam:* or *."""
    if required_action in granted_actions:
        return True
    service = required_action.split(":")[0]
    if "*" in granted_actions:
        return True
    if f"{service}:*" in granted_actions:
        return True
    return False


def scan_policy(path):
    with open(path) as f:
        doc = json.load(f)

    # Support raw policy documents or `aws iam get-policy-version` wrapper output
    policy_doc = doc.get("PolicyVersion", {}).get("Document", doc)
    granted = collect_actions(policy_doc)

    findings = []
    for name, required, desc in PRIVESC_PATTERNS:
        if all(action_matches(granted, req) for req in required):
            findings.append((name, desc))
    return granted, findings


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    any_findings = False
    for arg in sys.argv[1:]:
        for path in sorted(Path().glob(arg)) if any(c in arg for c in "*?") else [Path(arg)]:
            if not path.is_file():
                continue
            try:
                granted, findings = scan_policy(path)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[!] Skipping {path}: {e}")
                continue

            print(f"\n=== {path} ===")
            print(f"    Actions granted: {len(granted)}")
            if findings:
                any_findings = True
                for name, desc in findings:
                    print(f"    [RISK] {name}: {desc}")
            else:
                print("    No known privesc pattern matched.")

    if any_findings:
        print("\n[*] One or more policies match known privilege-escalation patterns.")
        print("    Document these in your remediation report with least-privilege recommendations.")
        sys.exit(2)
    else:
        print("\n[*] No known privesc patterns matched in the scanned policies.")


if __name__ == "__main__":
    main()
