# BloodHound CE Collectors & API Reference

## SharpHound (CE / .NET collector)

| Flag | Purpose |
|------|---------|
| `-c, --collectionmethods <m>` | Methods: `All`, `DCOnly`, `Session`, `LocalAdmin`, `ACL`, `Trusts`, `Group`, `GPOLocalGroup`, `Container`, `CertServices` |
| `--outputdirectory <dir>` | Directory to write the output ZIP |
| `-d, --domain <fqdn>` | Target domain |
| `--loop` | Repeat session collection in a loop |
| `--loopduration HH:MM:SS` | How long to loop |
| `--zipfilename <name>` | Name of output ZIP |
| `--ldapusername / --ldappassword` | Alternate LDAP credentials |
| `--stealth` | Reduced-footprint collection |

## bloodhound-ce-python (Linux)

| Flag | Purpose |
|------|---------|
| `-u <user>` | Username |
| `-p <pass>` | Password |
| `-d <domain>` | Domain FQDN |
| `-ns <ip>` | Nameserver (DC IP) |
| `-c All` | Collection methods |
| `--zip` | Compress output into a ZIP |
| `-k` | Use Kerberos authentication |

## AzureHound (Entra ID / Azure RM)

| Flag | Purpose |
|------|---------|
| `list` | Subcommand: collect all supported data |
| `-u <user>` | Username |
| `-p <pass>` | Password |
| `-t <tenant>` | Tenant domain or ID |
| `--jwt <token>` | Authenticate with an acquired JWT |
| `--refresh-token <rt>` | Authenticate with a refresh token |
| `-o <file>` | Output JSON file |

## BloodHound CE REST API (selected endpoints)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v2/login` | Obtain a session JWT (`login_method: secret`) |
| POST | `/api/v2/file-upload/start` | Begin a file-ingest job |
| PUT | `/api/v2/file-upload/{id}` | Upload collector ZIP/JSON to the job |
| POST | `/api/v2/file-upload/{id}/end` | Finalize and trigger ingestion |
| POST | `/api/v2/graphs/cypher` | Run a Cypher query, return graph data |
| GET | `/api/v2/domains` | List ingested domains |
| GET | `/api/v2/pathfinding` | Pathfinding between two nodes |

## Common Cypher snippets

```cypher
// Owned -> Domain Admins (RID 512)
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group)) WHERE g.objectid ENDS WITH "-512" RETURN p
// Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
// Entra Global Admins
MATCH p=(n)-[:AZGlobalAdmin*1..]->(:AZTenant) RETURN p
```
