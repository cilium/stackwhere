package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := root().Execute(); err != nil {
		os.Exit(1)
	}
}

func root() *cobra.Command {
	c := &cobra.Command{
		Use: "stackwhere",
	}

	const primaryGroupID = "primary"
	c.AddGroup(
		&cobra.Group{
			ID:    primaryGroupID,
			Title: "Available Commands:",
		},
	)

	listCmd := listCommand()
	listCmd.GroupID = primaryGroupID

	c.AddCommand(
		listCmd,
		versionCommand(),
	)

	return c
}
