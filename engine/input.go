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
		n := &Node{Port11434Public: true} // all visorlog findings are publicly exposed by definition

		rows.Scan(
			&n.HostIP, &n.HostHostname, &n.OrgName, &n.OrgCountry,
			&n.Sector, &n.TLD, &n.Source, &tagsStr, nil, &notes,
		)

		n.Tags = parseTags(tagsStr)
		for _, t := range n.Tags {
			switch t {
			case "TAKEOVER":
				n.AccountTakeover = true
			case "CVE-2025-63389":
				n.CVE202563389Vulnerable = true
			case "CLOUD":
				n.CloudProxy = true
			}
		}
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
