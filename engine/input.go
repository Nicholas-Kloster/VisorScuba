package engine

import (
	"database/sql"
	"encoding/json"
	"strings"

	_ "modernc.org/sqlite"
)

// Node is the flat input shape the Rego policy evaluates.
type Node struct {
	HostIP                  string                   `json:"host_ip"`
	HostHostname            string                   `json:"host_hostname"`
	OrgName                 string                   `json:"org_name"`
	OrgCountry              string                   `json:"org_country"`
	Sector                  string                   `json:"sector"`
	TLD                     string                   `json:"tld"`
	OllamaVersion           string                   `json:"ollama_version"`
	Port11434Public         bool                     `json:"port_11434_public"`
	Authenticated           bool                     `json:"authenticated"`
	CVE202563389Vulnerable  bool                     `json:"cve_2025_63389_vulnerable"`
	AccountTakeover         bool                     `json:"account_takeover"`
	CloudProxy              bool                     `json:"cloud_proxy"`
	Tags                    []string                 `json:"tags"`
	Models                  []map[string]interface{} `json:"models"`
	Source                  string                   `json:"source"`
	// ServiceClass is a human-readable label for what the finding
	// actually is (Ollama, MLflow, AutoGen Studio, etc.), derived from
	// the finding's tags. Before this field existed, AI.C1 hardcoded
	// "Unauthenticated Ollama" for every finding.
	ServiceClass string `json:"service_class"`
	// AgentPlatform / StorageACLOpen / DefaultCert are tag-derived flags
	// that drive the dedicated rules added alongside AI.C1.
	AgentPlatform  bool `json:"agent_platform"`
	StorageACLOpen bool `json:"storage_acl_open"`
	DefaultCert    bool `json:"default_cert"`
	// BrowserControl is true for the browser-automation backend tier
	// (CDP, Splash, Selenium Grid, Selenoid, Browserless, Playwright
	// MCP). An exposed one is unauthenticated remote browser control —
	// cookie/session theft, SSRF, and arbitrary in-page JS execution.
	BrowserControl bool `json:"browser_control"`
}

// classifyService maps a finding's tags to a human-readable service
// class. Unrecognized tag sets fall back to a generic label — never to
// "Ollama".
func classifyService(tags []string) string {
	has := func(t string) bool {
		for _, x := range tags {
			if x == t {
				return true
			}
		}
		return false
	}
	switch {
	case has("OLLAMA"):
		return "Ollama"
	case has("AUTOGEN-STUDIO"):
		return "AutoGen Studio"
	case has("UNAUTH-MLFLOW") || has("MLFLOW-ARTIFACT-BACKEND"):
		return "MLflow"
	case has("AZURE-BLOB-PUBLIC-LIST"):
		return "Azure Blob (public-list ACL)"
	// Browser-automation classes are checked before TRAEFIK-DEFAULT-CERT:
	// a host can carry both BROWSER-CONTROL and a default-cert tag, and
	// the browser-control identity is the load-bearing one.
	case has("BROWSERLESS"):
		return "Browserless"
	case has("UNAUTH-CDP"):
		return "Chrome DevTools Protocol"
	case has("UNAUTH-SELENIUM-GRID"):
		return "Selenium Grid"
	case has("UNAUTH-SELENOID"):
		return "Selenoid"
	case has("UNAUTH-SPLASH"):
		return "Splash render service"
	case has("PLAYWRIGHT-MCP"):
		return "Playwright MCP"
	case has("TRAEFIK-DEFAULT-CERT"):
		return "Traefik (default cert)"
	case has("AIRFLOW-EXPOSED"):
		return "Apache Airflow"
	case has("REDIS-EXPOSED"):
		return "Redis"
	case has("POSTGRES-EXPOSED"):
		return "PostgreSQL"
	case has("UNAUTH-API") || has("FASTAPI"):
		return "FastAPI service"
	default:
		return "AI/ML service"
	}
}

// applyTagDerivations populates the tag-derived flags on a Node. It
// replaces the old inline tag-switch in LoadFromDB and the hardcoded
// Port11434Public:true that made AI.C1 fire on every row.
func applyTagDerivations(n *Node) {
	n.ServiceClass = classifyService(n.Tags)
	for _, t := range n.Tags {
		switch t {
		case "TAKEOVER":
			n.AccountTakeover = true
		case "CVE-2025-63389":
			n.CVE202563389Vulnerable = true
		case "CLOUD":
			n.CloudProxy = true
		case "OLLAMA":
			// Port11434Public is Ollama-specific. Only Ollama findings
			// set it — not every VisorLog row.
			n.Port11434Public = true
		case "AUTOGEN-STUDIO", "UNAUTH-AGENT-PLATFORM":
			n.AgentPlatform = true
		case "AZURE-BLOB-PUBLIC-LIST":
			n.StorageACLOpen = true
		case "TRAEFIK-DEFAULT-CERT":
			n.DefaultCert = true
		case "BROWSER-CONTROL":
			n.BrowserControl = true
		}
	}
}

func (n *Node) ToMap() map[string]interface{} {
	data, _ := json.Marshal(n)
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	return m
}

// LoadFromDB reads all open findings from a VisorLog SQLite database.
func LoadFromDB(dbPath string) ([]*Node, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT host_ip, host_hostname, org_name, org_country,
		       sector, tld, source, tags, lifecycle_status, notes
		FROM events
		WHERE lifecycle_status = 'open'
		ORDER BY timestamp DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*Node
	for rows.Next() {
		var tagsStr, notes string
		n := &Node{}

		rows.Scan(
			&n.HostIP, &n.HostHostname, &n.OrgName, &n.OrgCountry,
			&n.Sector, &n.TLD, &n.Source, &tagsStr, nil, &notes,
		)

		n.Tags = parseTags(tagsStr)
		applyTagDerivations(n)
		if strings.Contains(notes, "signin_url") {
			n.AccountTakeover = true
		}

		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func parseTags(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var tags []string
	json.Unmarshal([]byte(s), &tags)
	return tags
}
