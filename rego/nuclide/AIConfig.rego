package nuclide_ai_baseline

import future.keywords.in

# NuClide AI Infrastructure Security Baseline v1.0
# CC0 — public domain, freely reusable.
#
# Input shape (VisorLog event / VisorGoose probe result):
#   host_ip, host_hostname, org_name, org_country, sector, tld
#   ollama_version, port_11434_public, authenticated
#   cve_2025_63389_vulnerable, account_takeover, cloud_proxy
#   models: [{name, is_cloud, system_prompt}]
#   tags: ["TAKEOVER", "CVE-2025-63389", "CLOUD", "RAG", "DISTILLED", "TOOLS"]

default score = 10
default max_score = 10

#──────────────────────────────────────────────────────────────
# CRITICAL denies  (score −3 each)
#──────────────────────────────────────────────────────────────

# AI.C1 — Unauthenticated AI service publicly exposed
deny[result] {
    input.port_11434_public == true
    result := {
        "id":          "AI.C1",
        "criticality": "Critical",
        "requirement": "AI services must not be publicly accessible without authentication",
        "details":     sprintf("Unauthenticated Ollama at %v (%v)", [input.host_ip, input.host_hostname]),
    }
}

# AI.C2 — Live account takeover via Ollama Connect
deny[result] {
    input.account_takeover == true
    result := {
        "id":          "AI.C2",
        "criticality": "Critical",
        "requirement": "Cloud API credentials must not be claimable via unauthenticated endpoints",
        "details":     sprintf("Live Ollama Connect claim URL at %v — cloud subscription takeover possible", [input.host_ip]),
    }
}

# AI.C3 — CVE-2025-63389: unauthenticated model injection
deny[result] {
    input.cve_2025_63389_vulnerable == true
    result := {
        "id":          "AI.C3",
        "criticality": "Critical",
        "requirement": "Model creation endpoint (/api/create) must require authentication",
        "details":     sprintf("CVE-2025-63389: unauthenticated system prompt injection at %v (Ollama %v)", [input.host_ip, input.ollama_version]),
    }
}

# AI.C4 — Government infrastructure with any critical finding
# Helper: true when any critical condition fires (avoids self-reference in deny)
has_critical_finding {
    input.port_11434_public == true
}
has_critical_finding {
    input.account_takeover == true
}
has_critical_finding {
    input.cve_2025_63389_vulnerable == true
}

deny[result] {
    input.sector == "government"
    has_critical_finding
    result := {
        "id":          "AI.C4",
        "criticality": "Critical",
        "requirement": "Government infrastructure must not expose critical AI security vulnerabilities",
        "details":     sprintf("Critical AI exposure on government infrastructure: %v (%v, %v)", [input.host_ip, input.org_name, input.org_country]),
    }
}

#──────────────────────────────────────────────────────────────
# HIGH warnings  (score −1 each)
#──────────────────────────────────────────────────────────────

# AI.H1 — Cloud API proxy quota exposed
warn[result] {
    input.cloud_proxy == true
    not input.account_takeover
    result := {
        "id":          "AI.H1",
        "criticality": "High",
        "requirement": "Cloud API proxies must not be publicly accessible without authentication",
        "details":     sprintf("Cloud API proxy exposed at %v — paid quota drainable without authentication", [input.host_ip]),
    }
}

# AI.H2 — RAG pipeline on government infrastructure
warn[result] {
    "RAG" in input.tags
    input.sector == "government"
    result := {
        "id":          "AI.H2",
        "criticality": "High",
        "requirement": "Document retrieval pipelines on government infrastructure must be authenticated",
        "details":     sprintf("Unauthenticated government RAG pipeline at %v (%v)", [input.host_ip, input.host_hostname]),
    }
}

# AI.H3 — Tool-calling model publicly exposed
warn[result] {
    "TOOLS" in input.tags
    result := {
        "id":          "AI.H3",
        "criticality": "High",
        "requirement": "Function-calling models must not be publicly accessible",
        "details":     sprintf("Tool-calling model at %v — prompt injection can chain to external function calls", [input.host_ip]),
    }
}

# AI.H4 — Healthcare sector AI exposure
warn[result] {
    input.sector == "healthcare"
    result := {
        "id":          "AI.H4",
        "criticality": "High",
        "requirement": "Healthcare AI deployments must be authenticated (PHI/PII risk)",
        "details":     sprintf("Unauthenticated AI on healthcare infrastructure at %v (%v)", [input.host_ip, input.org_name]),
    }
}

#──────────────────────────────────────────────────────────────
# MEDIUM info  (score −0, flagged only)
#──────────────────────────────────────────────────────────────

# AI.M1 — Knowledge-distilled model exposed
info[result] {
    "DISTILLED" in input.tags
    result := {
        "id":          "AI.M1",
        "criticality": "Medium",
        "requirement": "Knowledge-distilled models should be access-controlled",
        "details":     sprintf("Distilled model at %v encodes reasoning patterns of proprietary source model", [input.host_ip]),
    }
}

# AI.M2 — Custom AI persona on sensitive infrastructure
info[result] {
    some model in input.models
    model.system_prompt != ""
    input.sector in {"government", "healthcare", "military"}
    result := {
        "id":          "AI.M2",
        "criticality": "Medium",
        "requirement": "Custom AI personas on sensitive infrastructure must be reviewed and authorized",
        "details":     sprintf("Custom system prompt deployed on %v infrastructure at %v", [input.sector, input.host_ip]),
    }
}

#──────────────────────────────────────────────────────────────
# Scoring and summary
#──────────────────────────────────────────────────────────────

score = s {
    raw := max_score - (count(deny) * 3) - count(warn)
    s := max({0, raw})
}

violations = v {
    d := [r | r := deny[_]]
    w := [r | r := warn[_]]
    v := array.concat(d, w)
}

summary = {
    "score":          score,
    "max_score":      max_score,
    "compliance_pct": round((score / max_score) * 100),
    "violations":     violations,
    "info":           [r | r := info[_]],
    "passing":        count(violations) == 0,
}
