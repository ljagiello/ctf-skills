# Reference: Cloud Log Forensics with AWS Athena

## Athena Partition Projection

Partition projection eliminates the need for `ALTER TABLE ADD PARTITION` by automatically
inferring partition values at query time based on declared ranges. This is critical for
forensic tables that span long date ranges across multiple accounts and regions.

### Key TBLPROPERTIES

```sql
'projection.enabled' = 'true'
'projection.<column>.type' = 'date|enum|integer|injected'
'projection.<column>.range' = '<start>,<end>'   -- for date/integer
'projection.<column>.format' = 'yyyy/MM/dd'     -- for date
'projection.<column>.interval' = '1'            -- for date/integer
'projection.<column>.interval.unit' = 'DAYS'    -- DAYS|HOURS|MINUTES|SECONDS
'projection.<column>.values' = 'val1,val2'      -- for enum
'storage.location.template' = 's3://bucket/path/${column1}/${column2}'
```

## CloudTrail Log Structure

CloudTrail JSON fields relevant to forensics:

| Field | Description | Forensic Use |
|-------|-------------|--------------|
| userIdentity.arn | Caller identity | Attribute actions to actors |
| eventName | API call name | Identify suspicious operations |
| eventSource | AWS service | Scope investigation |
| sourceIPAddress | Origin IP | Detect external access |
| errorCode | AccessDenied etc. | Find unauthorized attempts |
| requestParameters | API parameters | Understand intent |
| responseElements | API response | Confirm impact |
| userAgent | Client software | Detect unusual tooling |
| tlsDetails | TLS version/cipher | Detect weak crypto |

## VPC Flow Log Fields

| Field | Type | Forensic Use |
|-------|------|--------------|
| srcaddr | IP | Identify source of traffic |
| dstaddr | IP | Identify destination |
| srcport | INT | Source port (ephemeral = client) |
| dstport | INT | Destination port (service identification) |
| protocol | INT | 6=TCP, 17=UDP, 1=ICMP |
| action | STRING | ACCEPT or REJECT |
| bytes | BIGINT | Volume of data transferred |
| packets | BIGINT | Packet count |
| start/end | BIGINT | Unix epoch timestamps |
| flow_direction | STRING | ingress or egress |

## S3 Access Log Fields

| Field | Forensic Use |
|-------|--------------|
| remote_ip | Source of S3 requests |
| requester | IAM identity or anonymous |
| operation | REST API operation (REST.GET.OBJECT, etc.) |
| key | S3 object path accessed |
| http_status | Success/failure indicator |
| bytes_sent | Data volume exfiltrated |
| total_time | Request duration |

## ALB Access Log Fields

| Field | Forensic Use |
|-------|--------------|
| client_ip | Source of web requests |
| request_url | Full URL with potential injection payloads |
| elb_status_code | ALB response (5xx = server-side issues) |
| target_status_code | Backend response |
| request_processing_time | ALB processing delay |
| user_agent | Client identification |

## Forensic Query Patterns

### Lateral Movement Indicators (VPC Flow Logs)
- Internal-to-internal traffic on management ports (22, 3389, 5985, 445)
- High connection counts between internal hosts
- Unusual protocol usage (ICMP tunneling)
- Traffic to honeypot IPs

### Privilege Escalation Indicators (CloudTrail)
- IAM policy attachment events
- CreateAccessKey for other users
- AssumeRole to high-privilege roles
- ConsoleLogin without MFA
- Security group modifications opening ingress

### Data Exfiltration Indicators (S3 + CloudTrail)
- Bulk GetObject from sensitive buckets
- PutBucketPolicy making buckets public
- CopyObject to external accounts
- DeleteBucketEncryption
- Large bytes_sent volumes from S3 access logs

### Web Attack Indicators (ALB)
- SQL injection patterns in URLs (UNION SELECT, SLEEP, WAITFOR)
- Path traversal (../../, /etc/passwd)
- XSS payloads (<script>, javascript:)
- Command injection (cmd.exe, /bin/sh)

## Protocol Number Reference

| Protocol Number | Name |
|----------------|------|
| 1 | ICMP |
| 6 | TCP |
| 17 | UDP |
| 47 | GRE |
| 50 | ESP |
| 58 | ICMPv6 |

## Common Suspicious Ports

| Port | Service | Concern |
|------|---------|---------|
| 22 | SSH | Lateral movement |
| 445 | SMB | Lateral movement, ransomware |
| 3389 | RDP | Lateral movement |
| 5985/5986 | WinRM | Lateral movement |
| 4444 | Metasploit default | C2 channel |
| 8080 | Alt HTTP | Proxy, backdoor |
| 1433 | MSSQL | Database access |
| 3306 | MySQL | Database access |
| 5432 | PostgreSQL | Database access |
| 6379 | Redis | Cache access |

### References

- AWS Athena CloudTrail table creation: https://docs.aws.amazon.com/athena/latest/ug/create-cloudtrail-table-partition-projection.html
- AWS VPC Flow Logs Athena integration: https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs-create-table-statement.html
- AWS ALB access logs Athena table: https://docs.aws.amazon.com/athena/latest/ug/create-alb-access-logs-table-partition-projection.html
- AWS Athena partition projection: https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html
- CloudTrail log analysis with Athena: https://aws.amazon.com/blogs/mt/optimize-querying-aws-cloudtrail-logs-with-partitioning-in-amazon-athena/
