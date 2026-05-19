[![Claude Code Friendly](https://img.shields.io/badge/Claude_Code-Friendly-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)

# VisorScuba

**OPA-powered AI infrastructure compliance scoring for NuClide findings.**

VisorScuba reads open findings from `nuclide.db` (VisorLog), evaluates each node against the NuClide AI Security Baseline Rego policies using Open Policy Agent, and produces ScubaGear-style per-node compliance scores (0–10). Inspired by [CISA's ScubaGear](https://github.com/cisagov/ScubaGear) — repurposed for AI/ML infrastructure.

Part of the [NuClide](https://nuclide-research.com) AI-LLM-Infrastructure-OSINT toolkit.

---

## Use with Claude Code

Claude Code can run VisorScuba assessments, interpret compliance gaps, and translate scores into remediation plans or disclosure drafts.

```
Run `visorscuba assess --db nuclide.db --json` and analyze the output. For every node scoring 0–3, describe the specific violations, what an attacker can do with each one, and what remediation the affected org needs to apply to reach a passing score.
```

```
I have a VisorScuba HTML report for 168 nodes. Identify the most common violation IDs, calculate what percentage of nodes fail each control, and draft a one-page executive summary with a prioritized remediation roadmap.
```

```
Run `visorscuba assess --db nuclide.db --org "government" --json` and cross-reference results against the VisorLog findings for the same IPs. For each government node with AI.C4 flagged, identify the underlying critical finding (C1/C2/C3) and draft a CERT disclosure stub.
```

---

## What It Does

Evaluates every open finding against 16 baseline controls:

| ID | Criticality | Control | Tag triggers |
|----|-------------|---------|--------------|
| AI.C1 | Critical | Unauthenticated AI service publicly exposed | `port_11434_public`, `agent_platform`, or any non-storage `service_class` |
| AI.C2 | Critical | Live Ollama Connect — account takeover possible | `account_takeover: true` |
| AI.C3 | Critical | CVE-2025-63389: unauthenticated system prompt injection | `cve_2025_63389_vulnerable: true` |
| AI.C4 | Critical | Government infrastructure with any critical finding | `sector: government` + any critical finding |
| AI.C5 | Critical | Cloud object store left world-readable (anonymous list ACL) | `storage_acl_open: true` |
| AI.C6 | Critical | Browser-automation backend exposed without authentication | `browser_control: true` |
| **AI.C7** | **Critical** | **Pooled-account upstream proxy with publicly-readable account/token counters (Insight #39 architecture)** | `POOL-LEAK`, `POOLED-ACCOUNT-PUBLIC`, `ACCOUNT-COUNTER-PUBLIC` |
| AI.H1 | High | Cloud API proxy quota drainable without auth | `cloud_proxy: true` |
| AI.H2 | High | RAG pipeline on government infrastructure | `RAG` tag + `sector: government` |
| AI.H3 | High | Tool-calling model publicly exposed (prompt injection → function call chain) | `TOOLS` tag |
| AI.H4 | High | Healthcare AI deployment without authentication (PHI/PII risk) | `sector: healthcare` |
| AI.H5 | High | Default-config TLS proxy (e.g. Traefik default cert) fronting an AI stack | `default_cert: true` |
| **AI.H6** | **High** | **Install wizard accessible — admin-claim-window open (first POST claims admin)** | `SETUP-OPEN`, `TAKEOVER-VECTOR`, `INSTALL-WIZARD-EXPOSED` |
| AI.M1 | Medium | Knowledge-distilled model exposed | `DISTILLED` tag |
| AI.M2 | Medium | Custom AI persona on sensitive infrastructure (gov / healthcare / military) | `models[].system_prompt` non-empty + `sector ∈ {government, healthcare, military}` |
| **AI.M3** | **Medium** | **Development server exposed in production (source-map paths, unminified bundles, dev-mode WebSocket)** | `DEV-MODE`, `BUILD-LEAK`, `VITE-DEV-EXPOSED`, `WEBPACK-DEV-EXPOSED`, `DJANGO-DEBUG-TRUE` |

**Bold** entries shipped in the v0.2 series (AI.H6 / AI.M3 / AI.C7 land
in the 3e34f4c commit alongside the 2026-05-19 sub2api population survey
that surfaced the gaps). The other three (AI.C5 / AI.C6 / AI.H5) shipped
earlier and were missing from the README table; this update closes that
gap.

Scoring: `10 − (critical_count × 3) − warn_count`, floor 0.

---

## Install

```bash
git clone https://github.com/Nicholas-Kloster/VisorScuba
cd VisorScuba
go build -o visorscuba .
```

---

## Usage

```bash
# Assess all open findings
visorscuba assess --db nuclide.db

# Filter to a specific org
visorscuba assess --db nuclide.db --org "Dinas Kominfo"

# JSON output
visorscuba assess --db nuclide.db --json

# HTML report
visorscuba assess --db nuclide.db --report report.html

# List embedded policies
visorscuba policies
```

---

## Rego Policies

`rego/nuclide/` — NuClide AI Security Baseline (this repo, CC0)

`rego/scubagear/` — CISA ScubaGear policies copied verbatim (CC0, public domain)

Both are embedded at compile time via `//go:embed all:rego`. No runtime policy files required.

---

## Input Shape

VisorScuba reads from VisorLog's `nuclide.db`. The engine maps each SQLite row to the Rego input object:

```json
{
  "host_ip": "1.2.3.4",
  "host_hostname": "ollama.example.gov",
  "org_name": "Example Agency",
  "sector": "government",
  "port_11434_public": true,
  "account_takeover": false,
  "cve_2025_63389_vulnerable": true,
  "cloud_proxy": false,
  "models": [{"name": "llama3", "system_prompt": "", "is_cloud": false}],
  "tags": ["CVE-2025-63389"]
}
```

---

## Ecosystem

```
VisorGoose ──┐
aimap      ──┼──► VisorLog (nuclide.db) ──► VisorScuba assess ──► scores / HTML report
ollama-recon─┘
```

- [VisorLog](https://github.com/Nicholas-Kloster/VisorLog) — findings ledger (data source)
- [VisorGoose](https://github.com/Nicholas-Kloster/VisorGoose) — multi-source AI service discovery
- [aimap](https://github.com/Nicholas-Kloster/aimap) — deep AI/ML infrastructure fingerprinter
- [AI-LLM-Infrastructure-OSINT](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT) — case study repository

---

_NuClide Research · [nuclide-research.com](https://nuclide-research.com)_

---

## About

Maintained by **[Nicholas Michael Kloster](https://github.com/Nicholas-Kloster)** as part of [**NuClide**](https://nuclide-research.com) — independent AI infrastructure security research.

CISA disclosures: [CVE-2025-4364](https://nvd.nist.gov/vuln/detail/CVE-2025-4364) · [ICSA-25-140-11](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-11)
