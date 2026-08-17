# API Reference — Performing GraphQL Introspection Attack

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | Send GraphQL introspection queries and depth test payloads |
| `json` | Parse schema responses and format results |
| `argparse` | CLI argument parsing for URL, auth headers, depth limits |

## Installation

```bash
pip install requests
```

## CLI Interface

```bash
python agent.py introspect --url <graphql_endpoint> [--auth-header "Bearer token"]
python agent.py depth --url <graphql_endpoint> [--max-depth 10]
```

## Core Functions

### `run_introspection(url, headers)` — Execute `__schema` introspection query

```python
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
"""

def run_introspection(url, headers=None):
    """Execute full introspection query and extract schema details."""
    resp = requests.post(
        url,
        json={"query": INTROSPECTION_QUERY},
        headers=headers or {},
        timeout=30,
    )
    resp.raise_for_status()
    schema = resp.json().get("data", {}).get("__schema", {})

    types = [t for t in schema.get("types", []) if not t["name"].startswith("__")]
    queries = []
    mutations = []
    sensitive_fields = []

    for t in types:
        for field in (t.get("fields") or []):
            if t["name"] == schema.get("queryType", {}).get("name"):
                queries.append(field["name"])
            if t["name"] == schema.get("mutationType", {}).get("name"):
                mutations.append(field["name"])
            if any(kw in field["name"].lower() for kw in SENSITIVE_PATTERNS):
                sensitive_fields.append({"type": t["name"], "field": field["name"]})

    return {
        "types_count": len(types),
        "queries": queries,
        "mutations": mutations,
        "sensitive_fields": sensitive_fields,
        "introspection_enabled": True,
    }
```

### `test_depth_limit(url, max_depth, headers)` — Test query depth enforcement

```python
def test_depth_limit(url, max_depth=15, headers=None):
    """Send increasingly nested queries to detect missing depth limits."""
    results = []
    for depth in range(1, max_depth + 1):
        # Build a nested query using __typename
        nested = "{ __typename " * depth + "}" * depth
        query = f"query DepthTest {nested}"

        try:
            resp = requests.post(
                url,
                json={"query": query},
                headers=headers or {},
                timeout=10,
            )
            status = resp.status_code
            has_errors = "errors" in resp.json()
            results.append({
                "depth": depth,
                "status": status,
                "blocked": has_errors and status != 200,
            })
            if has_errors:
                return {
                    "max_allowed_depth": depth - 1,
                    "depth_limit_enforced": True,
                    "results": results,
                }
        except requests.Timeout:
            return {
                "max_allowed_depth": depth - 1,
                "depth_limit_enforced": True,
                "reason": "timeout",
                "results": results,
            }

    return {
        "max_allowed_depth": max_depth,
        "depth_limit_enforced": False,
        "severity": "high",
        "detail": f"No depth limit detected up to {max_depth} levels",
        "results": results,
    }
```

### `test_batch_query(url, headers)` — Test for batching attacks

```python
def test_batch_query(url, headers=None):
    """Test if the endpoint allows batched queries (alias-based brute force)."""
    batch = [
        {"query": '{ alias0: __typename }'},
        {"query": '{ alias1: __typename }'},
        {"query": '{ alias2: __typename }'},
    ]
    resp = requests.post(url, json=batch, headers=headers or {}, timeout=10)
    return {
        "batch_supported": resp.status_code == 200 and isinstance(resp.json(), list),
        "responses": len(resp.json()) if isinstance(resp.json(), list) else 0,
    }
```

## Sensitive Field Patterns

```python
SENSITIVE_PATTERNS = [
    "password", "token", "secret", "credential", "ssn",
    "credit_card", "api_key", "apikey", "private_key",
    "auth", "session", "otp", "pin", "cvv",
]
```

## Output Format

```json
{
  "url": "https://api.example.com/graphql",
  "introspection_enabled": true,
  "types_count": 45,
  "queries": ["users", "orders", "admin_dashboard"],
  "mutations": ["createUser", "deleteAccount", "updatePassword"],
  "sensitive_fields": [
    {"type": "User", "field": "password_hash"},
    {"type": "Session", "field": "auth_token"}
  ],
  "depth_limit": {
    "enforced": false,
    "max_tested": 15,
    "severity": "high"
  },
  "batch_queries": {
    "supported": true,
    "severity": "medium"
  }
}
```
