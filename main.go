package main

import (
	"embed"
	"os"

	"github.com/Nicholas-Kloster/visorscuba/cmd"
	"github.com/Nicholas-Kloster/visorscuba/engine"
)

//go:embed all:rego
var regoFS embed.FS

func main() {
	engine.RegoFS = regoFS
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
