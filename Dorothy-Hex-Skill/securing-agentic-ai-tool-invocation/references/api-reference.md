# API Reference — Agentic AI Tool Invocation Controls

## NVIDIA NeMo Guardrails

Install: `pip install nemoguardrails`

| API | Description |
|-----|-------------|
| `RailsConfig.from_path("./guardrails_config")` | Load rails config (config.yml, prompts.yml, *.co flows) |
| `RailsConfig.from_content(yaml_content=..., colang_content=...)` | Load config inline |
| `LLMRails(config)` | Build a guarded LLM wrapper |
| `rails.generate(messages=[...])` | Run input/output/tool rails around generation |
| `rails.register_action(fn, name=...)` | Register a custom tool/action under rail control |

Built-in flows: `self check input`, `self check output`, `self check facts`. Rail types: `input`, `output`, `dialog`, `retrieval`, `execution/tool`.

## jsonschema

Install: `pip install jsonschema`

| API | Description |
|-----|-------------|
| `validate(instance=args, schema=schema)` | Raise `ValidationError` if args violate schema |
| `additionalProperties: false` | Deny-by-default extra arguments |
| `pattern` / `maxLength` / `enum` | Constrain argument values (e.g. recipient domain allowlist) |

## AWS STS (boto3) — scoped identity

Install: `pip install boto3`

| API | Description |
|-----|-------------|
| `sts.assume_role(RoleArn, RoleSessionName, Policy, DurationSeconds)` | Assume a role with an inline session policy that *further restricts* permissions |
| `DurationSeconds=900` | Short-lived (15 min) credentials, least privilege |
| `boto3.Session(aws_access_key_id=..., aws_session_token=...)` | Use the scoped creds for the tool call |

## Policy decision contract

| Decision | Meaning | Action |
|----------|---------|--------|
| `allow` | Allowlisted, args valid, low impact | Execute tool |
| `require_approval` | High-impact tool | Route to human-in-the-loop, fail-closed |
| `deny` | Unknown tool or invalid args | Reject and log |

## External References

- NeMo Guardrails docs: https://docs.nvidia.com/nemo/guardrails/
- jsonschema docs: https://python-jsonschema.readthedocs.io/
- OWASP Agentic AI Top 10: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
