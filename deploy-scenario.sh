#!/usr/bin/env bash
# deploy-scenario.sh
# Thin wrapper around CloudGoat's own CLI so scenario create/destroy is
# consistent and always confirms the target account first.
#
# Usage:
#   ./deploy-scenario.sh create iam_privesc_by_rollback
#   ./deploy-scenario.sh destroy iam_privesc_by_rollback
#   ./deploy-scenario.sh list

set -euo pipefail

CLOUDGOAT_DIR="./cloudgoat"
PROFILE="${AWS_PROFILE:-cloudgoat}"

if [ ! -d "$CLOUDGOAT_DIR" ]; then
    echo "[!] cloudgoat/ not found — run setup.sh first"
    exit 1
fi

cmd="${1:-}"
scenario="${2:-}"

confirm_account() {
    echo "[*] Target AWS account (profile: $PROFILE):"
    aws sts get-caller-identity --profile "$PROFILE"
    read -rp "    Continue against this account? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
}

case "$cmd" in
    list)
        (cd "$CLOUDGOAT_DIR" && python3 cloudgoat.py list scenarios)
        ;;
    create)
        [ -n "$scenario" ] || { echo "Usage: $0 create <scenario_name>"; exit 1; }
        confirm_account
        (cd "$CLOUDGOAT_DIR" && python3 cloudgoat.py create "$scenario" --profile "$PROFILE")
        ;;
    destroy)
        [ -n "$scenario" ] || { echo "Usage: $0 destroy <scenario_name>"; exit 1; }
        (cd "$CLOUDGOAT_DIR" && python3 cloudgoat.py destroy "$scenario" --profile "$PROFILE")
        echo "[*] Verify no residual resources in the AWS console (S3, IAM, EC2, Lambda)."
        ;;
    *)
        echo "Usage: $0 {list|create <scenario>|destroy <scenario>}"
        exit 1
        ;;
esac
