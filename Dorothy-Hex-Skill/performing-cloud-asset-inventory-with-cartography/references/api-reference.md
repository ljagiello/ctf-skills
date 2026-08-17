# API Reference: Cartography Cloud Asset Inventory

## Libraries Used

| Library | Purpose |
|---------|---------|
| `neo4j` | Neo4j Python driver for graph database queries |
| `subprocess` | Execute Cartography CLI sync commands |
| `boto3` | AWS SDK for supplementary asset lookups |
| `json` | Parse Cartography output and Neo4j results |

## Installation

```bash
# Cartography
pip install cartography

# Neo4j Python driver
pip install neo4j

# Neo4j server (Docker)
docker run -d --name neo4j \
    -p 7474:7474 -p 7687:7687 \
    -e NEO4J_AUTH=neo4j/changeme \
    neo4j:5
```

## Authentication

### Neo4j Connection
```python
from neo4j import GraphDatabase
import os

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ["NEO4J_PASS"]

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
```

### AWS Credentials for Sync
```bash
# Cartography uses standard AWS credential chain
export AWS_PROFILE=security-audit
# Or: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
```

## CLI Reference

### Sync AWS Assets to Neo4j
```bash
cartography --neo4j-uri bolt://localhost:7687 \
    --neo4j-user neo4j \
    --neo4j-password-env-var NEO4J_PASS \
    --aws-sync-all-profiles
```

### Sync Specific AWS Services
```bash
cartography --neo4j-uri bolt://localhost:7687 \
    --neo4j-user neo4j \
    --neo4j-password-env-var NEO4J_PASS \
    --aws-requested-syncs ec2:instances,iam:users,s3
```

### Key CLI Flags

| Flag | Description |
|------|-------------|
| `--neo4j-uri` | Neo4j Bolt URI |
| `--neo4j-user` | Neo4j username |
| `--neo4j-password-env-var` | Env var containing Neo4j password |
| `--aws-sync-all-profiles` | Sync all configured AWS profiles |
| `--aws-requested-syncs` | Sync specific AWS services |
| `--gcp-requested-syncs` | Sync specific GCP services |
| `--azure-sync-all-subscriptions` | Sync all Azure subscriptions |
| `--statsd-enabled` | Enable StatsD metrics |
| `--update-tag` | Custom tag for this sync run |

## Cypher Queries for Security Analysis

### Find Public S3 Buckets
```python
def find_public_s3_buckets(driver):
    query = """
    MATCH (s:S3Bucket)
    WHERE s.anonymous_access = true
    RETURN s.name AS bucket, s.region AS region, s.arn AS arn
    """
    with driver.session() as session:
        return [dict(r) for r in session.run(query)]
```

### Find IAM Users Without MFA
```python
def find_users_without_mfa(driver):
    query = """
    MATCH (u:AWSUser)
    WHERE NOT (u)-[:HAS_MFA_DEVICE]->(:MFADevice)
      AND u.password_enabled = true
    RETURN u.name AS username, u.arn AS arn,
           u.password_last_used AS last_login
    """
    with driver.session() as session:
        return [dict(r) for r in session.run(query)]
```

### Find EC2 Instances with Public IPs and Permissive Security Groups
```python
def find_exposed_instances(driver):
    query = """
    MATCH (i:EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
          -[:MEMBER_OF_IP_RULE]->(rule:IpRule)
    WHERE i.publicipaddress IS NOT NULL
      AND rule.cidr_ip = '0.0.0.0/0'
      AND rule.fromport <= 22
      AND rule.toport >= 22
    RETURN DISTINCT i.instanceid AS instance_id,
           i.publicipaddress AS public_ip,
           sg.name AS security_group
    """
    with driver.session() as session:
        return [dict(r) for r in session.run(query)]
```

### Map Cross-Account IAM Trust Relationships
```python
def find_cross_account_roles(driver):
    query = """
    MATCH (role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(principal:AWSPrincipal)
    WHERE principal.arn CONTAINS ':root'
      AND NOT principal.arn CONTAINS role.accountid
    RETURN role.arn AS role_arn,
           principal.arn AS trusted_principal,
           role.accountid AS role_account
    """
    with driver.session() as session:
        return [dict(r) for r in session.run(query)]
```

### Find Unencrypted RDS Instances
```python
def find_unencrypted_rds(driver):
    query = """
    MATCH (rds:RDSInstance)
    WHERE rds.storage_encrypted = false
    RETURN rds.db_instance_identifier AS db_name,
           rds.engine AS engine,
           rds.publicly_accessible AS public
    """
    with driver.session() as session:
        return [dict(r) for r in session.run(query)]
```

## Cartography Node Types

| Node Label | Represents |
|------------|-----------|
| `AWSAccount` | AWS account |
| `AWSUser` | IAM user |
| `AWSRole` | IAM role |
| `AWSPolicy` | IAM policy |
| `EC2Instance` | EC2 instance |
| `EC2SecurityGroup` | Security group |
| `S3Bucket` | S3 bucket |
| `RDSInstance` | RDS database instance |
| `LambdaFunction` | Lambda function |
| `EKSCluster` | EKS Kubernetes cluster |

## Output Format

```json
{
  "sync_time": "2025-01-15T10:30:00Z",
  "accounts_synced": 3,
  "nodes_created": 12450,
  "relationships_created": 34200,
  "findings": {
    "public_s3_buckets": 2,
    "users_without_mfa": 5,
    "exposed_instances": 3,
    "cross_account_trusts": 8,
    "unencrypted_databases": 4
  }
}
```
