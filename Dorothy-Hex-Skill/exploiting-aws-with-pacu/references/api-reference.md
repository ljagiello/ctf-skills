# Pacu — Command and Module Reference

## Console Commands

| Command | Description |
|---------|-------------|
| `set_keys` | Add/update AWS keys for the active session |
| `swap_keys` | Switch between stored key sets in the session |
| `import_keys <profile>` | Import keys from `~/.aws/credentials` (use `--all` for every profile) |
| `whoami` | Show the active principal and key details |
| `ls` / `list` | List available modules |
| `search <term>` | Search modules by name/keyword |
| `help <module>` | Show a module's help and arguments |
| `run <module> [args]` | Execute a module (alias: `exec`) |
| `data <service\|all>` | Query enumerated data from the session DB |
| `services` | List services with collected data |
| `regions` | Show / set in-scope AWS regions (`set_regions`) |
| `sessions` / `swap_session` | Manage multiple engagement sessions |
| `exit` / `quit` | Leave the console |

## Non-Interactive (shell) Flags

| Flag | Description |
|------|-------------|
| `--session <name>` | Select/create the session |
| `--module-name <module>` | Module to run |
| `--module-args "<args>"` | Arguments passed to the module |
| `--exec` | Run the module immediately and exit |
| `--set-regions <r1 r2>` | Constrain regions |

## Key Modules

| Module | Category | Purpose |
|--------|----------|---------|
| `iam__enum_users_roles_policies_groups` | Recon | Enumerate all IAM principals/policies |
| `iam__enum_permissions` | Recon | Resolve current principal's effective permissions |
| `iam__privesc_scan` | Privesc | Detect/exploit privilege-escalation paths |
| `iam__backdoor_users_keys` | Persistence | Create backdoor access key on a user |
| `iam__backdoor_assume_role` | Persistence | Add attacker trust to a role |
| `ec2__enum` | Recon | Enumerate EC2 instances/volumes/snapshots |
| `ec2__startup_shell_script` | Exec | Inject user-data startup script |
| `s3__download_bucket` | Exfil | Download S3 bucket objects |
| `secrets__enum` | Credential Access | Enumerate Secrets Manager / SSM secrets |
| `lambda__enum` | Recon | Enumerate Lambda functions and configs |

## Common privesc primitives checked by `iam__privesc_scan`

`iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy`,
`iam:AttachGroupPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`,
`iam:CreateAccessKey`, `iam:UpdateLoginProfile`, `iam:PassRole` + `lambda:CreateFunction`,
`iam:PassRole` + `ec2:RunInstances`, `sts:AssumeRole`, `glue:CreateDevEndpoint`,
`cloudformation:CreateStack` + `iam:PassRole`.
