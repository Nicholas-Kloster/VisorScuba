package engine

import "testing"

// classifyService maps a finding's tags to a human-readable service
// class. Before this fix, every VisorLog finding was hardcoded as
// "Unauthenticated Ollama" because Port11434Public was set true for all
// rows. The classifier is what lets AI.C1 produce an accurate label and
// lets the rego pick the right rule.

func TestClassifyService_Ollama(t *testing.T) {
	got := classifyService([]string{"OLLAMA", "CVE-2025-63389"})
	if got != "Ollama" {
		t.Errorf("classifyService(OLLAMA tags) = %q; want Ollama", got)
	}
}

func TestClassifyService_AutoGenStudio(t *testing.T) {
	got := classifyService([]string{"AUTOGEN-STUDIO", "UNAUTH-AGENT-PLATFORM"})
	if got != "AutoGen Studio" {
		t.Errorf("classifyService(AUTOGEN-STUDIO) = %q; want AutoGen Studio", got)
	}
}

func TestClassifyService_AzureBlobPublicList(t *testing.T) {
	got := classifyService([]string{"AZURE-BLOB-PUBLIC-LIST", "ACL-MISCONFIG"})
	if got != "Azure Blob (public-list ACL)" {
		t.Errorf("classifyService(AZURE-BLOB-PUBLIC-LIST) = %q; want Azure Blob (public-list ACL)", got)
	}
}

func TestClassifyService_TraefikDefaultCert(t *testing.T) {
	got := classifyService([]string{"TRAEFIK-DEFAULT-CERT", "LITELLM-PHOENIX-SHARED-HOST"})
	if got != "Traefik (default cert)" {
		t.Errorf("classifyService(TRAEFIK-DEFAULT-CERT) = %q; want Traefik (default cert)", got)
	}
}

func TestClassifyService_MLflow(t *testing.T) {
	got := classifyService([]string{"UNAUTH-MLFLOW", "ARTIFACT-WASBS"})
	if got != "MLflow" {
		t.Errorf("classifyService(UNAUTH-MLFLOW) = %q; want MLflow", got)
	}
}

func TestClassifyService_FallbackGeneric(t *testing.T) {
	// Unrecognized tags → a generic label, NOT "Ollama".
	got := classifyService([]string{"SOMETHING-NEW", "WIDGET"})
	if got != "AI/ML service" {
		t.Errorf("classifyService(unknown tags) = %q; want generic 'AI/ML service'", got)
	}
}

func TestClassifyService_EmptyTags(t *testing.T) {
	got := classifyService(nil)
	if got != "AI/ML service" {
		t.Errorf("classifyService(nil) = %q; want generic 'AI/ML service'", got)
	}
}

// Port11434Public must only be true for actual Ollama findings — not
// hardcoded for every row.
func TestNode_Port11434_OnlyForOllama(t *testing.T) {
	ollama := nodeFromTags([]string{"OLLAMA"})
	if !ollama.Port11434Public {
		t.Error("OLLAMA finding should have Port11434Public = true")
	}
	autogen := nodeFromTags([]string{"AUTOGEN-STUDIO"})
	if autogen.Port11434Public {
		t.Error("AUTOGEN-STUDIO finding must NOT have Port11434Public = true (that flag is Ollama-specific)")
	}
}

// nodeFromTags is a tiny test helper that builds a Node the way
// LoadFromDB would, given a tag set.
func nodeFromTags(tags []string) *Node {
	n := &Node{Tags: tags}
	applyTagDerivations(n)
	return n
}
