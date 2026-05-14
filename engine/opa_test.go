package engine

import (
	"context"
	"embed"
	"os"
	"strings"
	"testing"
)

// The engine's Assess() reads from the package-level RegoFS, which main
// normally sets from an //go:embed of the repo-root rego/ dir. Go embed
// cannot reach ../rego, so engine/rego/nuclide/AIConfig.rego is a
// test-only copy. TestRegoCopyInSync (below) fails if it drifts from the
// canonical ../rego/nuclide/AIConfig.rego — one source of truth, enforced.
//
//go:embed all:rego
var testRegoFS embed.FS

// TestRegoCopyInSync guards against the engine/rego test copy drifting
// from the canonical repo-root rego/nuclide policy.
func TestRegoCopyInSync(t *testing.T) {
	canonical, err := os.ReadFile("../rego/nuclide/AIConfig.rego")
	if err != nil {
		t.Skipf("canonical rego not found (%v); skipping drift check", err)
	}
	copyb, err := os.ReadFile("rego/nuclide/AIConfig.rego")
	if err != nil {
		t.Fatalf("test rego copy missing: %v", err)
	}
	if string(canonical) != string(copyb) {
		t.Fatal("engine/rego/nuclide/AIConfig.rego has drifted from " +
			"../rego/nuclide/AIConfig.rego — re-copy it: " +
			"cp rego/nuclide/AIConfig.rego engine/rego/nuclide/")
	}
}

// assess is a test helper: it points RegoFS at the test-embedded rego
// tree, runs Assess, restores RegoFS, and returns the result.
func assess(t *testing.T, n *Node) *Result {
	t.Helper()
	saved := RegoFS
	RegoFS = testRegoFS
	defer func() { RegoFS = saved }()
	res, err := Assess(context.Background(), n.ToMap())
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	return res
}

func findViolation(res *Result, id string) map[string]interface{} {
	for _, v := range res.Violations {
		if v["id"] == id {
			return v
		}
	}
	return nil
}

// An Ollama finding still fires AI.C1 and the label still says Ollama.
func TestAssess_Ollama_FiresC1WithOllamaLabel(t *testing.T) {
	n := &Node{HostIP: "203.0.113.10", HostHostname: "ollama.example",
		Tags: []string{"OLLAMA"}}
	applyTagDerivations(n)
	res := assess(t, n)
	v := findViolation(res, "AI.C1")
	if v == nil {
		t.Fatal("Ollama finding should fire AI.C1")
	}
	if !strings.Contains(v["details"].(string), "Ollama") {
		t.Errorf("AI.C1 details should mention Ollama; got %q", v["details"])
	}
}

// An AutoGen Studio finding fires AI.C1 but the label says AutoGen
// Studio — NOT Ollama. This is the core bug the patch fixes.
func TestAssess_AutoGenStudio_FiresC1WithCorrectLabel(t *testing.T) {
	n := &Node{HostIP: "203.0.113.11", HostHostname: "",
		Tags: []string{"AUTOGEN-STUDIO", "UNAUTH-AGENT-PLATFORM"}}
	applyTagDerivations(n)
	res := assess(t, n)
	v := findViolation(res, "AI.C1")
	if v == nil {
		t.Fatal("AutoGen Studio finding should still fire AI.C1 (it's a critical exposure)")
	}
	d := v["details"].(string)
	if strings.Contains(d, "Ollama") {
		t.Errorf("AI.C1 must NOT say Ollama for an AutoGen Studio finding; got %q", d)
	}
	if !strings.Contains(d, "AutoGen Studio") {
		t.Errorf("AI.C1 should name AutoGen Studio; got %q", d)
	}
}

// An Azure-blob-public-list finding fires the dedicated AI.C5 rule and
// does NOT double-fire under AI.C1.
func TestAssess_AzureBlob_FiresC5NotC1(t *testing.T) {
	n := &Node{HostIP: "203.0.113.12", HostHostname: "blobimgstore.example",
		Tags: []string{"AZURE-BLOB-PUBLIC-LIST", "ACL-MISCONFIG"}}
	applyTagDerivations(n)
	res := assess(t, n)
	if findViolation(res, "AI.C5") == nil {
		t.Error("Azure-blob-public-list finding should fire AI.C5")
	}
	if findViolation(res, "AI.C1") != nil {
		t.Error("Azure-blob-public-list finding should NOT also fire AI.C1 (AI.C5 is dedicated)")
	}
}

// A Traefik-default-cert finding fires AI.H5 and does not fire AI.C1.
func TestAssess_TraefikDefaultCert_FiresH5NotC1(t *testing.T) {
	n := &Node{HostIP: "203.0.113.13", HostHostname: "",
		Tags: []string{"TRAEFIK-DEFAULT-CERT", "LITELLM-PHOENIX-SHARED-HOST"}}
	applyTagDerivations(n)
	res := assess(t, n)
	if findViolation(res, "AI.H5") == nil {
		t.Error("Traefik-default-cert finding should fire AI.H5")
	}
	if findViolation(res, "AI.C1") != nil {
		t.Error("Traefik-default-cert finding should NOT fire AI.C1")
	}
}

// An MLflow finding fires AI.C1 with the MLflow label.
func TestAssess_MLflow_FiresC1WithMLflowLabel(t *testing.T) {
	n := &Node{HostIP: "203.0.113.14", HostHostname: "mlflow.example",
		Tags: []string{"UNAUTH-MLFLOW", "ARTIFACT-WASBS"}}
	applyTagDerivations(n)
	res := assess(t, n)
	v := findViolation(res, "AI.C1")
	if v == nil {
		t.Fatal("MLflow finding should fire AI.C1")
	}
	d := v["details"].(string)
	if strings.Contains(d, "Ollama") {
		t.Errorf("AI.C1 must not say Ollama for an MLflow finding; got %q", d)
	}
	if !strings.Contains(d, "MLflow") {
		t.Errorf("AI.C1 should name MLflow; got %q", d)
	}
}
