# AWS IAM Federation Inventory

Inventories all IAM roles with federated trust policies (SAML / OIDC) across multiple AWS accounts by assuming a read-only role in each account.

Designed for audit trail, drift detection, and SOX/SOC change-control reporting.

---

## What it does

- Assumes `aws-readonly-role` in each target account via STS
- Paginates through all IAM roles in each account
- Filters for roles with a `Federated` principal in their trust policy
- Captures IdP type (SAML / OIDC), IdP ARN, last used date, and creation date
- Outputs a CSV report

---

## Setup

```bash
pip install -r requirements.txt

cp accounts.txt.example accounts.txt
# Edit accounts.txt — add one account ID per line
```

---

## Usage

```bash
# Print to stdout
python scripts/inventory/get_federated_roles.py --accounts accounts.txt

# Write to CSV
python scripts/inventory/get_federated_roles.py --accounts accounts.txt --output federated_roles.csv
```

### Example output

| account_id   | role_name          | role_arn | idp_type | idp_arn | last_used  | created_date |
|--------------|--------------------|----------|----------|---------|------------|--------------|
| 123456789012 | OktaSSOAdminRole   | arn:...  | SAML     | arn:aws:iam::123456789012:saml-provider/Okta | 2026-06-10 | 2024-01-15 |
| 123456789012 | GithubActionsRole  | arn:...  | OIDC     | arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com | 2026-06-17 | 2024-03-01 |

---

## Requirements

- AWS credentials with `sts:AssumeRole` permission
- `aws-readonly-role` must exist in each target account with `iam:ListRoles` and `iam:GetRole` permissions
- Python 3.10+
