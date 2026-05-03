package engine

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

// suppress unused import warning — embed used via RegoFS type
var _ embed.FS

// RegoFS must be set by main before calling Assess.
var RegoFS embed.FS

// Result is the output of a single assessment.
type Result struct {
	Score         int                      `json:"score"`
	MaxScore      int                      `json:"max_score"`
	CompliancePct int                      `json:"compliance_pct"`
	Passing       bool                     `json:"passing"`
	Violations    []map[string]interface{} `json:"violations"`
	Info          []map[string]interface{} `json:"info"`
}

// Assess evaluates input against the NuClide AI baseline.
func Assess(ctx context.Context, input map[string]interface{}) (*Result, error) {
	modules, err := loadModules("nuclide")
	if err != nil {
		return nil, err
	}

	opts := []func(*rego.Rego){
		rego.Query("data.nuclide_ai_baseline.summary"),
		rego.Input(input),
	}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}

	r := rego.New(opts...)
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("rego eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("no results from policy evaluation")
	}

	raw, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type from policy")
	}

	result := &Result{
		Score:         toInt(raw["score"]),
		MaxScore:      toInt(raw["max_score"]),
		CompliancePct: toInt(raw["compliance_pct"]),
		Passing:       toBool(raw["passing"]),
		Violations:    toSlice(raw["violations"]),
		Info:          toSlice(raw["info"]),
	}
	return result, nil
}

func loadModules(dir string) (map[string]string, error) {
	path := fmt.Sprintf("rego/%s", dir)
	modules := map[string]string{}

	err := fs.WalkDir(RegoFS, path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".rego") {
			return err
		}
		data, err := RegoFS.ReadFile(p)
		if err != nil {
			return err
		}
		modules[p] = string(data)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	return modules, nil
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func toBool(v interface{}) bool {
	b, _ := v.(bool)
	return b
}

func toSlice(v interface{}) []map[string]interface{} {
	s, _ := v.([]interface{})
	var out []map[string]interface{}
	for _, item := range s {
		if m, ok := item.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}
