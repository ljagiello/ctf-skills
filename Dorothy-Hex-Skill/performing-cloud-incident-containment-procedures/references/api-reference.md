# API Reference: AWS Cloud Incident Containment

## Libraries Used

| Library | Purpose |
|---------|---------|
| `boto3` | AWS SDK for EC2, IAM, Security Groups, and CloudTrail |
| `json` | Parse and log containment actions |
| `datetime` | Timestamp containment events |

## Installation

```bash
pip install boto3
```

## Authentication

```python
import boto3
import os

session = boto3.Session(
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    region_name=os.environ.get("AWS_REGION", "us-east-1"),
)

ec2 = session.client("ec2")
iam = session.client("iam")
```

## Containment Actions

### Isolate EC2 Instance (Security Group Quarantine)
```python
def isolate_instance(instance_id):
    """Replace instance security groups with a quarantine SG that blocks all traffic."""
    # Create quarantine SG if it doesn't exist
    vpc_id = ec2.describe_instances(
        InstanceIds=[instance_id]
    )["Reservations"][0]["Instances"][0]["VpcId"]

    try:
        quarantine_sg = ec2.create_security_group(
            GroupName="quarantine-no-access",
            Description="IR Quarantine — blocks all inbound/outbound",
            VpcId=vpc_id,
        )
        sg_id = quarantine_sg["GroupId"]
        # Revoke default outbound rule
        ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
    except ec2.exceptions.ClientError:
        # SG already exists
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["quarantine-no-access"]}]
        )
        sg_id = sgs["SecurityGroups"][0]["GroupId"]

    # Apply quarantine SG (replaces all existing SGs)
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[sg_id],
    )
    return {"instance_id": instance_id, "quarantine_sg": sg_id, "action": "isolated"}
```

### Disable IAM Access Keys
```python
def disable_user_access_keys(username):
    """Disable all access keys for a compromised IAM user."""
    keys = iam.list_access_keys(UserName=username)
    disabled = []
    for key in keys["AccessKeyMetadata"]:
        if key["Status"] == "Active":
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive",
            )
            disabled.append(key["AccessKeyId"])
    return {"username": username, "keys_disabled": disabled}
```

### Revoke IAM Role Sessions
```python
def revoke_role_sessions(role_name):
    """Revoke all active sessions for an IAM role."""
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="RevokeOlderSessions",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                }
            }]
        }),
    )
    return {"role": role_name, "action": "sessions_revoked"}
```

### Snapshot EBS Volume for Forensics
```python
def snapshot_instance_volumes(instance_id):
    """Create forensic snapshots of all attached EBS volumes."""
    instance = ec2.describe_instances(InstanceIds=[instance_id])
    volumes = instance["Reservations"][0]["Instances"][0].get("BlockDeviceMappings", [])
    snapshots = []
    for vol in volumes:
        vol_id = vol["Ebs"]["VolumeId"]
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f"IR forensic snapshot — {instance_id} — {vol_id}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "Purpose", "Value": "incident-response"},
                    {"Key": "SourceInstance", "Value": instance_id},
                ]
            }],
        )
        snapshots.append({"volume_id": vol_id, "snapshot_id": snap["SnapshotId"]})
    return snapshots
```

### Stop Instance (Preserve State)
```python
def stop_instance(instance_id):
    """Stop instance without terminating to preserve memory and disk."""
    ec2.stop_instances(InstanceIds=[instance_id])
    return {"instance_id": instance_id, "action": "stopped"}
```

### Block Public S3 Bucket Access
```python
s3 = session.client("s3")

def block_public_bucket(bucket_name):
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return {"bucket": bucket_name, "action": "public_access_blocked"}
```

## Output Format

```json
{
  "incident_id": "IR-2025-001",
  "containment_time": "2025-01-15T10:30:00Z",
  "actions_taken": [
    {"action": "isolate_instance", "target": "i-0abc123", "status": "success"},
    {"action": "disable_access_keys", "target": "compromised-user", "keys_disabled": 2},
    {"action": "snapshot_volumes", "target": "i-0abc123", "snapshots": 2},
    {"action": "stop_instance", "target": "i-0abc123", "status": "success"}
  ]
}
```
