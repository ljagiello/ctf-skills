# API Reference: Cloud Storage Forensic Acquisition

## Libraries Used

| Library | Purpose |
|---------|---------|
| `boto3` | AWS S3 object listing, download, and versioning |
| `json` | Parse object metadata and access logs |
| `hashlib` | Generate SHA-256 hashes for evidence integrity |
| `datetime` | Filter objects by time range for incident scope |

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

s3 = session.client("s3")
```

## AWS S3 Forensic Operations

### List All Object Versions (Including Deleted)
```python
def list_all_versions(bucket, prefix=""):
    """List all object versions including delete markers for forensic timeline."""
    paginator = s3.get_paginator("list_object_versions")
    versions = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for v in page.get("Versions", []):
            versions.append({
                "key": v["Key"],
                "version_id": v["VersionId"],
                "last_modified": v["LastModified"].isoformat(),
                "size": v["Size"],
                "is_latest": v["IsLatest"],
                "etag": v["ETag"],
            })
        for dm in page.get("DeleteMarkers", []):
            versions.append({
                "key": dm["Key"],
                "version_id": dm["VersionId"],
                "last_modified": dm["LastModified"].isoformat(),
                "is_delete_marker": True,
                "is_latest": dm["IsLatest"],
            })
    return sorted(versions, key=lambda v: v["last_modified"])
```

### Download Object with Integrity Verification
```python
import hashlib

def forensic_download(bucket, key, output_path, version_id=None):
    """Download an S3 object and compute SHA-256 hash for chain of custody."""
    params = {"Bucket": bucket, "Key": key}
    if version_id:
        params["VersionId"] = version_id

    resp = s3.get_object(**params)
    sha256 = hashlib.sha256()

    with open(output_path, "wb") as f:
        for chunk in resp["Body"].iter_chunks(chunk_size=8192):
            f.write(chunk)
            sha256.update(chunk)

    return {
        "key": key,
        "version_id": version_id,
        "output_path": output_path,
        "sha256": sha256.hexdigest(),
        "content_type": resp.get("ContentType"),
        "last_modified": resp["LastModified"].isoformat(),
        "metadata": resp.get("Metadata", {}),
    }
```

### Recover Deleted Objects
```python
def recover_deleted_objects(bucket, prefix=""):
    """Find and restore objects with delete markers."""
    recovered = []
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for dm in page.get("DeleteMarkers", []):
            if dm["IsLatest"]:
                # Remove delete marker to restore the object
                s3.delete_object(
                    Bucket=bucket,
                    Key=dm["Key"],
                    VersionId=dm["VersionId"],
                )
                recovered.append({
                    "key": dm["Key"],
                    "delete_marker_removed": dm["VersionId"],
                })
    return recovered
```

### Get S3 Access Logs for Incident Timeline
```python
def get_access_logs(log_bucket, prefix, start_time, end_time):
    """Parse S3 access logs to build forensic timeline."""
    paginator = s3.get_paginator("list_objects_v2")
    log_entries = []
    for page in paginator.paginate(Bucket=log_bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if start_time <= obj["LastModified"].isoformat() <= end_time:
                resp = s3.get_object(Bucket=log_bucket, Key=obj["Key"])
                content = resp["Body"].read().decode("utf-8")
                for line in content.strip().split("\n"):
                    log_entries.append(line)
    return log_entries
```

### Acquire Bucket Metadata
```python
def acquire_bucket_metadata(bucket):
    """Collect all bucket configuration for forensic evidence."""
    metadata = {"bucket": bucket}

    metadata["versioning"] = s3.get_bucket_versioning(Bucket=bucket)
    metadata["encryption"] = s3.get_bucket_encryption(Bucket=bucket).get(
        "ServerSideEncryptionConfiguration", {}
    )
    try:
        metadata["logging"] = s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled", {})
    except Exception:
        metadata["logging"] = None
    try:
        metadata["lifecycle"] = s3.get_bucket_lifecycle_configuration(Bucket=bucket).get("Rules", [])
    except Exception:
        metadata["lifecycle"] = []
    try:
        metadata["policy"] = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except Exception:
        metadata["policy"] = None

    return metadata
```

## Evidence Chain of Custody

```python
import json
from datetime import datetime, timezone

def create_chain_of_custody(evidence_items):
    """Generate a chain-of-custody record for acquired evidence."""
    record = {
        "acquisition_time": datetime.now(timezone.utc).isoformat(),
        "examiner": os.environ.get("EXAMINER_NAME", "automated"),
        "case_id": os.environ.get("CASE_ID", "unknown"),
        "items": [],
    }
    for item in evidence_items:
        record["items"].append({
            "source": f"s3://{item['bucket']}/{item['key']}",
            "local_path": item["output_path"],
            "sha256": item["sha256"],
            "acquired_at": datetime.now(timezone.utc).isoformat(),
        })
    return record
```

## Output Format

```json
{
  "bucket": "incident-bucket",
  "acquisition_time": "2025-01-15T10:30:00Z",
  "total_objects": 1542,
  "total_versions": 3891,
  "deleted_objects_recovered": 23,
  "evidence_items": [
    {
      "key": "sensitive/data.csv",
      "version_id": "abc123",
      "sha256": "a1b2c3d4e5f6...",
      "last_modified": "2025-01-14T08:00:00Z"
    }
  ]
}
```
