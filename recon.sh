#!/usr/bin/env bash
# recon.sh
# Read-only reconnaissance against the CloudGoat target account:
#   - enumerates IAM users, roles, and attached/inline policies
#   - flags S3 buckets with public access or missing block-public-access
#   - dumps everything to timestamped files under ./recon-output/
#
# Read-only by design (list/get/describe calls only) — safe to run
# repeatedly against your own lab account.
#
# Usage: ./recon.sh [aws-profile]

set -euo pipefail

PROFILE="${1:-${AWS_PROFILE:-cloudgoat}}"
OUTDIR="recon-output/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] Using AWS profile: $PROFILE"
echo "[*] Output directory:  $OUTDIR"

echo "[*] Caller identity..."
aws sts get-caller-identity --profile "$PROFILE" | tee "$OUTDIR/caller-identity.json"

# ---------------------------------------------------------------- IAM ----
echo "[*] Enumerating IAM users..."
aws iam list-users --profile "$PROFILE" > "$OUTDIR/iam-users.json"

echo "[*] Enumerating IAM roles..."
aws iam list-roles --profile "$PROFILE" > "$OUTDIR/iam-roles.json"

echo "[*] Enumerating IAM policies (customer-managed)..."
aws iam list-policies --scope Local --profile "$PROFILE" > "$OUTDIR/iam-policies.json"

echo "[*] Pulling attached + inline policies for every user..."
: > "$OUTDIR/iam-user-policies.txt"
for user in $(jq -r '.Users[].UserName' "$OUTDIR/iam-users.json"); do
    echo "== $user ==" >> "$OUTDIR/iam-user-policies.txt"
    aws iam list-attached-user-policies --user-name "$user" --profile "$PROFILE" \
        >> "$OUTDIR/iam-user-policies.txt" 2>&1
    aws iam list-user-policies --user-name "$user" --profile "$PROFILE" \
        >> "$OUTDIR/iam-user-policies.txt" 2>&1
done

echo "[*] Pulling attached + inline policies for every role..."
: > "$OUTDIR/iam-role-policies.txt"
for role in $(jq -r '.Roles[].RoleName' "$OUTDIR/iam-roles.json"); do
    echo "== $role ==" >> "$OUTDIR/iam-role-policies.txt"
    aws iam list-attached-role-policies --role-name "$role" --profile "$PROFILE" \
        >> "$OUTDIR/iam-role-policies.txt" 2>&1
    aws iam list-role-policies --role-name "$role" --profile "$PROFILE" \
        >> "$OUTDIR/iam-role-policies.txt" 2>&1
done

# ----------------------------------------------------------------- S3 ----
echo "[*] Enumerating S3 buckets..."
aws s3api list-buckets --profile "$PROFILE" > "$OUTDIR/s3-buckets.json"

echo "[*] Checking public-access block + policy status per bucket..."
: > "$OUTDIR/s3-exposure.txt"
for bucket in $(jq -r '.Buckets[].Name' "$OUTDIR/s3-buckets.json"); do
    echo "== $bucket ==" >> "$OUTDIR/s3-exposure.txt"
    aws s3api get-public-access-block --bucket "$bucket" --profile "$PROFILE" \
        >> "$OUTDIR/s3-exposure.txt" 2>&1 || echo "  (no public-access-block set — check manually)" >> "$OUTDIR/s3-exposure.txt"
    aws s3api get-bucket-policy-status --bucket "$bucket" --profile "$PROFILE" \
        >> "$OUTDIR/s3-exposure.txt" 2>&1 || echo "  (no bucket policy)" >> "$OUTDIR/s3-exposure.txt"
    aws s3api get-bucket-acl --bucket "$bucket" --profile "$PROFILE" \
        >> "$OUTDIR/s3-exposure.txt" 2>&1
done

echo ""
echo "[*] Recon complete. Review:"
echo "    $OUTDIR/iam-user-policies.txt   (look for wildcard Action/Resource)"
echo "    $OUTDIR/iam-role-policies.txt   (look for iam:PassRole + compute create perms)"
echo "    $OUTDIR/s3-exposure.txt         (look for IsPublic: true, missing block-public-access)"
echo ""
echo "Feed iam-*-policies.txt into scripts/iam-privesc-scan.py for automated flagging."
