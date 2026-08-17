# Web LLM Attacks — Resources

## OWASP Top 10 for LLM Applications (2025)

- LLM01 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- LLM02 Insecure Output Handling — https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/
- LLM03 Training Data Poisoning
- LLM05 Improper Output Handling
- LLM06 Excessive Agency
- LLM07 System Prompt Leakage
- LLM08 Vector / Embedding Weaknesses (RAG pipelines)
- LLM09 Misinformation
- LLM10 Unbounded Consumption (Denial of Wallet, DoS)

OWASP LLM Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
OWASP Top 10 for Agentic Applications (2026) — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ (ASI01 Goal Hijack, ASI02 Excessive Agency, ASI04 Confidential Data Leakage, ASI05 Supply Chain, ASI10 Rogue Agents)
OWASP LLM Security Verification Standard — https://owasp.org/www-project-llm-verification-standard/

## Standards

- NIST AI 100-1 — https://www.nist.gov/itl/ai-risk-management-framework
- ISO/IEC 42001:2023 — AI Management System
- IEEE 7000 / 7001 / 7010 — AI Ethics
- PCI DSS 4.0 (Req 6.5, 11) for LLM-using payment systems
- GDPR Art 22 (right to explanation), Art 5 (data minimization), Art 25 (privacy by design)
- OAuth 2.1 — securing LLM API access; PKCE mandatory

## Notable CVEs

- **CVE-2025-53773** GitHub Copilot / VS Code — RCE via prompt injection writing `.vscode/settings.json`
- **CVE-2025-54135 / CVE-2025-54136** Cursor IDE — preset-command execution via prompt injection
- **CVE-2024-5565** Vanna.AI — RCE via text-to-SQL prompt injection (SQL stacked queries)
- **CVE-2024-12866** xpander.ai — system-prompt leakage
- **CVE-2024-7043** llama.cpp / GGUF — buffer overflow in tokenizer
- **CVE-2024-7042** LangChain (CVE family) — SSRF via document loaders
- Hugging Face safetensors / pickle deserialization — model files invoke arbitrary code on load
- ChatGPT plugin auth flaws (multiple) — OAuth misconfigurations leak tokens
- LangChain SQL agent — unsafe `tool.run()` + SQLDatabaseToolkit
- Anthropic / OpenAI prompt-injection in tool-use payloads

## Tooling

### Offensive / testing

- **garak** — LLM vulnerability scanner (`--probes prompt_injection`, `injection.sql`, `injection.cmd`) — https://github.com/leondz/garak
- **promptbench** — robustness benchmarks
- **Guardrails AI / NVIDIA NeMo Guardrails / Lakera Guard / Rebuff** — input/output filters (also useful as red-team target)
- **PAIR / Tree of Attacks (TAP)** — automated jailbreak generation
- **PromptInject** — synthetic prompt-injection corpora
- **AgentDojo** — agent benchmark suite for goal-hijack tests
- **gpt-jailbreak** / DAN prompt collections
- **llm-vulnerability-scanner** — community tool aggregator

### Defensive / verification

- **Lakera Guard / Rebuff** — runtime prompt-injection detection
- **NVIDIA NeMo Guardrails** — programmable safety rails
- **OpenAI moderation endpoint**
- **Anthropic Constitutional AI** prompts

## Research

- "Prompt Injection: A Comprehensive Survey" (2024)
- Simon Willison — https://simonwillison.net/tags/prompt-injection/
- Anthropic alignment research blog
- LangChain Blog — prompt-injection writeups
- arXiv:2306.05499 (Universal & Transferable Adversarial Attacks)
- arXiv:2310.17138 (Indirect Prompt Injection)
- "Many-Shot Jailbreaking" (Anthropic 2024)
- "Sleeper Agents" (Anthropic 2024)
- "Tree of Attacks" (TAP) paper
- Schulhoff et al. "Ignore This Title and HackAPrompt" (NeurIPS 2023)

## Secure coding

- OWASP LLM Cheat Sheet (above)
- **Treat LLM output as untrusted user input** — context-aware sanitization at every sink
- Input/output structured formats (JSON schemas with strict validation)
- Tool allowlists (block destructive APIs by default)
- Human-in-the-loop for any state-changing action
- Privilege separation: LLM runs with minimum credentials; sensitive APIs go through approval workflows
- Audit logging of every prompt + response + tool invocation

## Training & community

- HackAPrompt — https://www.hackaprompt.com/
- promptingguide.ai — Lilian Weng / Andrej Karpathy / etc.
- OWASP LLM Security working group (Slack / GitHub)
- HackerOne / Bugcrowd — LLM-app bug bounties (OpenAI, Anthropic, Cohere, Hugging Face)
- @simonw, @llm_sec, @riley_goodside on X/Twitter
- DEFCON AI Village — https://aivillage.org/

## Bug bounty programs (LLM scope)

- OpenAI — https://openai.com/security/
- Anthropic — https://www.anthropic.com/responsible-disclosure
- Google AI / Bard — Google VRP
- Microsoft Bug Bounty — AI/Azure OpenAI scope
- GitHub — Copilot scope
- Hugging Face — model security disclosures
- LangChain — security@langchain.dev

## Reference docs

- LangChain security guide — https://python.langchain.com/docs/security
- LlamaIndex security
- OpenAI usage policies
- Anthropic acceptable use policy
- OpenAI moderation API
- AWS Bedrock guardrails
- Vertex AI safety filters

## Practice / labs

- TryHackMe — Prompt injection rooms
- PortSwigger Web LLM labs — https://portswigger.net/web-security/llm-attacks
- HackAPrompt CTF
- Lakera Gandalf — https://gandalf.lakera.ai/
