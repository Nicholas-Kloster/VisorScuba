# VisorScuba

OPA-powered AI infrastructure compliance scoring for NuClide findings. Reads `nuclide.db` (VisorLog), evaluates every open finding against ~10 NuClide AI Security Baseline Rego controls (AI.C1–C4 critical, AI.H1–H4 high, AI.M1–M2 medium), emits ScubaGear-style 0–10 per-node scores. Inspired by CISA's ScubaGear, repurposed for AI/ML infrastructure.

## Language
Go

## Build & Run
```
go build -o visorscuba .
visorscuba assess --db nuclide.db
visorscuba assess --db nuclide.db --json
visorscuba assess --db nuclide.db --org "government" --html report.html
visorscuba policies      # list embedded Rego modules
go test ./...
```

## Claude Code Notes
- Check README for full CLI surface, control taxonomy, and input shape
- Rego policies live in `rego/nuclide/` (NuClide AI Security Baseline) + `rego/scubagear/` (CISA upstream, CC0)
- Findings flow: aimap / VisorRAG / probes → VisorLog (nuclide.db) → VisorScuba (scores)
- Built with [Claude Code](https://claude.ai/code)
