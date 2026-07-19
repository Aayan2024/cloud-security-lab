#!/usr/bin/env bash
# setup.sh
# Installs prerequisites and pulls CloudGoat (Rhino Security Labs' official
# open-source vulnerable-by-design AWS environment generator).
#
# Run this once. Requires: an AWS account you own or have explicit written
# authorization to test against, with a budget alarm set — CloudGoat creates
# real billable resources.

set -euo pipefail

echo "[*] Checking prerequisites..."
command -v python3  >/dev/null || { echo "python3 not found — install it first"; exit 1; }
command -v pip3     >/dev/null || { echo "pip3 not found — install it first";    exit 1; }
command -v terraform >/dev/null || echo "[!] terraform not found — install >=1.0 from terraform.io before deploying scenarios"
command -v aws       >/dev/null || echo "[!] aws-cli not found — install with: pip3 install awscli"

echo "[*] Cloning CloudGoat (official repo)..."
if [ ! -d "cloudgoat" ]; then
    git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
fi

cd cloudgoat
echo "[*] Installing CloudGoat's Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo "[*] Verifying AWS CLI identity..."
aws sts get-caller-identity || {
    echo "[!] AWS CLI isn't configured. Run: aws configure --profile cloudgoat"
    exit 1
}

cat <<'EOF'

[*] Setup complete.

Next steps:
  1. Create a *dedicated* IAM user/profile for this lab (never your root or
     day-to-day account) with programmatic access.
  2. export AWS_PROFILE=cloudgoat   (or pass --profile to every command)
  3. Use scripts/deploy-scenario.sh to stand up a scenario.
  4. Set an AWS Budget alert before you start — CloudGoat resources bill
     to your account until destroyed.

EOF
