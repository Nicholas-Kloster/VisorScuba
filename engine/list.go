package engine

import (
	"io/fs"
	"strings"
)

// ListPolicies returns all embedded Rego module paths.
func ListPolicies() ([]string, error) {
	var names []string
	err := fs.WalkDir(RegoFS, "rego", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return err
		}
		names = append(names, path)
		return nil
	})
	return names, err
}
