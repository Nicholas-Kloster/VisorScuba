package cmd

import (
	"github.com/spf13/cobra"
)

var flagDB string

var rootCmd = &cobra.Command{
	Use:   "visorscuba",
	Short: "NuClide AI Security Baseline — OPA-powered assessment engine",
	Long: `VisorScuba evaluates AI infrastructure findings against the NuClide AI Security
Baseline, producing ScubaGear-style compliance scores and reports.

Embeds CISA's ScubaGear Rego policies (CC0) alongside NuClide's AI-specific baseline.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagDB, "db", "visorlog.db", "VisorLog SQLite database")
	rootCmd.AddCommand(assessCmd)
	rootCmd.AddCommand(policiesCmd)
}
