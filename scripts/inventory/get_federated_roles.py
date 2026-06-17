#!/usr/bin/env python3
"""
Inventories all IAM roles with federated trust policies across multiple AWS accounts.
Assumes the role 'aws-readonly-role' in each account and outputs a CSV report.

Usage:
    python get_federated_roles.py --accounts accounts.txt --output federated_roles.csv
    python get_federated_roles.py --accounts accounts.txt  # prints to stdout
"""

import argparse
import boto3
import csv
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError


ASSUME_ROLE_NAME = "aws-readonly-role"
SESSION_NAME = "federated-role-inventory"


def assume_role(account_id: str) -> boto3.Session:
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{ASSUME_ROLE_NAME}"
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION_NAME)
    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def list_all_roles(iam_client) -> list:
    roles = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        roles.extend(page["Roles"])
    return roles


def extract_federated_principals(trust_policy: dict) -> list[dict]:
    """Returns list of {type, principal} for each federated principal in the trust policy."""
    federated = []
    for statement in trust_policy.get("Statement", []):
        principal = statement.get("Principal", {})
        if isinstance(principal, dict):
            for key, value in principal.items():
                if key == "Federated":
                    values = [value] if isinstance(value, str) else value
                    for v in values:
                        idp_type = "SAML" if "saml-provider" in v else "OIDC" if "oidc-provider" in v else "Unknown"
                        federated.append({"idp_type": idp_type, "idp_arn": v})
    return federated


def get_role_last_used(iam_client, role_name: str) -> dict:
    try:
        response = iam_client.get_role(RoleName=role_name)
        last_used = response["Role"].get("RoleLastUsed", {})
        last_used_date = last_used.get("LastUsedDate")
        return {
            "last_used_date":   last_used_date.strftime("%Y-%m-%d %H:%M:%S UTC") if last_used_date else "Never",
            "last_used_region": last_used.get("Region", "N/A"),
        }
    except ClientError:
        return {"last_used_date": "Unknown", "last_used_region": "Unknown"}


def inventory_account(account_id: str) -> list[dict]:
    print(f"  Processing account {account_id}...", file=sys.stderr)
    try:
        session = assume_role(account_id)
        iam = session.client("iam")
        roles = list_all_roles(iam)
    except ClientError as e:
        print(f"  [WARN] Could not access account {account_id}: {e}", file=sys.stderr)
        return []

    rows = []
    for role in roles:
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        federated_principals = extract_federated_principals(trust_policy)
        if not federated_principals:
            continue

        last_used = get_role_last_used(iam, role["RoleName"])

        for fp in federated_principals:
            rows.append({
                "account_id":       account_id,
                "role_name":        role["RoleName"],
                "role_arn":         role["Arn"],
                "idp_type":         fp["idp_type"],
                "idp_arn":          fp["idp_arn"],
                "last_used_date":   last_used["last_used_date"],
                "last_used_region": last_used["last_used_region"],
                "created_date":     role["CreateDate"].strftime("%Y-%m-%d"),
                "path":             role["Path"],
            })

    print(f"  Found {len(rows)} federated role(s) in {account_id}", file=sys.stderr)
    return rows


def main():
    parser = argparse.ArgumentParser(description="Inventory federated IAM roles across AWS accounts")
    parser.add_argument("--accounts", required=True, help="Path to file with one account ID per line")
    parser.add_argument("--output", help="Output CSV file path (default: stdout)")
    args = parser.parse_args()

    with open(args.accounts) as f:
        account_ids = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Scanning {len(account_ids)} account(s)...", file=sys.stderr)

    all_rows = []
    for account_id in account_ids:
        all_rows.extend(inventory_account(account_id))

    fieldnames = ["account_id", "role_name", "role_arn", "idp_type", "idp_arn", "last_used_date", "last_used_region", "created_date", "path"]

    output = open(args.output, "w", newline="") if args.output else sys.stdout
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(all_rows)

    if args.output:
        output.close()
        print(f"\nDone. {len(all_rows)} total federated role(s) written to {args.output}", file=sys.stderr)
    else:
        print(f"\nDone. {len(all_rows)} total federated role(s) found.", file=sys.stderr)


if __name__ == "__main__":
    main()
