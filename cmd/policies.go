package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/visorscuba/engine"
	"github.com/spf13/cobra"
)

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "List embedded Rego policy modules",
	RunE: func(cmd *cobra.Command, args []string) error {
		names, err := engine.ListPolicies()
		if err != nil {
			return err
		}
		fmt.Println("Embedded policy modules:")
		for _, n := range names {
			fmt.Printf("  %s\n", n)
		}
		return nil
	},
}
