# llm-failover-guard

**Zero-dependency multi-provider LLM API key failover router and automated GitHub Pull Request security triage CLI for open-source maintainers.**

Maintained by **Youssef Lebkhachi** ([@youssefu](https://github.com/youssefu)).

## Why `llm-failover-guard`?

Open-source maintainers and developer tool authors frequently deal with two bottlenecks when automating repository workflows:
1. **Single-provider rate limits and transient outages** during automated PR reviews, issue triage, and release note generation.
2. **Accidental secret leaks and unsafe code patterns** introduced in community pull requests (`shell=True`, `eval()`, DOM XSS sinks, or misconfigured `pull_request_target` workflows).

`llm-failover-guard` solves both in a single, zero-dependency Python package and CLI that runs locally or inside GitHub Actions:
- **Circuit-Breaker API Key Ring (`FailoverRouter`)**: Round-robin rotation across [OpenAI API](https://platform.openai.com/docs/overview), Groq, DeepSeek, Mistral, Together AI, and local [Ollama](https://ollama.com/) endpoints with exponential cooldown backoff, per-slot latency tracking, and automatic key redaction.
- **Static & AI-Ready PR Security Triage (`scan`)**: Scans files, diffs, or full repositories for leaked credentials (`SEC001`), unsafe subprocess execution (`SEC002`), dynamic code execution (`SEC003`), DOM XSS sinks (`SEC004`), and risky GitHub Actions triggers (`SEC005`), emitting clean Markdown tables for PR comments or JSON for CI pipelines.

## Quickstart

```bash
# 1. Scan a repository or PR checkout for leaked secrets and security sinks
python3 llm_failover_guard.py scan . --fail-on-high

# 2. Emit JSON findings for automated CI / Codex PR review pipelines
python3 llm_failover_guard.py scan . --format json

# 3. Run a deterministic simulation of multi-provider rate-limit failover
python3 llm_failover_guard.py simulate-failover --json
```

## Using the Multi-Provider Failover Router in Python

```python
from llm_failover_guard import FailoverRouter, KeySlot

router = FailoverRouter([
    KeySlot(provider="openai", name="codex-primary", api_key="sk-proj-...", model="gpt-5"),
    KeySlot(provider="ollama", name="local-fallback", api_key="local", model="qwen3:8b"),
])

result = router.execute_with_failover(
    prompt="Review this pull request diff for backwards-incompatible API changes."
)
print(result["response"])
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT © Youssef Lebkhachi ([@youssefu](https://github.com/youssefu))
