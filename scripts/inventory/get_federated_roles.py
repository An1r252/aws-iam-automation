#!/usr/bin/env python3
"""
Inventories all IAM roles with federated trust policies across multiple AWS accounts.
Assumes the role 'aws-readonly-role' in each account and outputs a CSV report.

Usage:
    python get_federated_roles.py --accounts accounts.txt --profile my-gimme-profile --output federated_roles.csv
    python get_federated_roles.py --accounts accounts.txt --profile my-gimme-profile
"""

import argparse
import boto3
import csv
import sys
from botocore.exceptions import ClientError


ASSUME_ROLE_NAME = "aws-readonly-role"
SESSION_NAME = "federated-role-inventory"


def get_base_session(profile: str) -> boto3.Session:
    """Returns a boto3 session using the specified gimme-aws-creds profile."""
    session = boto3.Session(profile_name=profile)
    # Validate the session works before proceeding
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    print(
        f"Logged in as: {identity['Arn']} (account: {identity['Account']})",
        file=sys.stderr,
    )
    return session


def assume_role(base_session: boto3.Session, account_id: str) -> boto3.Session:
    sts = base_session.client("sts")
    role_arn = "arn:aws:iam::{}:role/{}".format(account_id, ASSUME_ROLE_NAME)
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


def extract_federated_principals(trust_policy: dict) -> list:
    """Returns list of {idp_type, idp_arn} for each federated principal in the trust policy."""
    federated = []
    for statement in trust_policy.get("Statement", []):
        principal = statement.get("Principal", {})
        if isinstance(principal, dict):
            for key, value in principal.items():
                if key == "Federated":
                    values = [value] if isinstance(value, str) else value
                    for v in values:
                        if "saml-provider" in v:
                            idp_type = "SAML"
                        elif "oidc-provider" in v:
                            idp_type = "OIDC"
                        else:
                            idp_type = "Unknown"
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


def inventory_account(base_session: boto3.Session, account_id: str) -> list:
    print("  Processing account {}...".format(account_id), file=sys.stderr)
    try:
        session = assume_role(base_session, account_id)
        iam = session.client("iam")
        roles = list_all_roles(iam)
    except ClientError as e:
        print("  [WARN] Could not access account {}: {}".format(account_id, e), file=sys.stderr)
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

    print("  Found {} federated role(s) in {}".format(len(rows), account_id), file=sys.stderr)
    return rows


def main():
    parser = argparse.ArgumentParser(description="Inventory federated IAM roles across AWS accounts")
    parser.add_argument("--accounts", required=True, help="Path to file with one account ID per line")
    parser.add_argument("--profile", required=True, help="AWS profile name from gimme-aws-creds (~/.aws/credentials)")
    parser.add_argument("--output", help="Output CSV file path (default: stdout)")
    args = parser.parse_args()

    try:
        base_session = get_base_session(args.profile)
    except Exception as e:
        print("[ERROR] Could not authenticate with profile '{}': {}".format(args.profile, e), file=sys.stderr)
        sys.exit(1)

    with open(args.accounts) as f:
        account_ids = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print("Scanning {} account(s)...".format(len(account_ids)), file=sys.stderr)

    all_rows = []
    for account_id in account_ids:
        all_rows.extend(inventory_account(base_session, account_id))

    fieldnames = ["account_id", "role_name", "role_arn", "idp_type", "idp_arn", "last_used_date", "last_used_region", "created_date", "path"]

    output = open(args.output, "w", newline="") if args.output else sys.stdout
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(all_rows)

    if args.output:
        output.close()
        print("\nDone. {} total federated role(s) written to {}".format(len(all_rows), args.output), file=sys.stderr)
    else:
        print("\nDone. {} total federated role(s) found.".format(len(all_rows)), file=sys.stderr)


if __name__ == "__main__":
    main()
