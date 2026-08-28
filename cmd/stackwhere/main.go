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

const (
	jsonFlagName    = "json"
	dwarvesFlagName = "dwarf"
)

func jsonOutput(cmd *cobra.Command) bool {
	jsonFlag, err := cmd.Flags().GetBool(jsonFlagName)
	if err != nil {
		return false
	}
	return jsonFlag
}

func dwarves(cmd *cobra.Command) []string {
	dwarves, _ := cmd.Flags().GetStringArray(dwarvesFlagName)
	return dwarves
}

func root() *cobra.Command {
	c := &cobra.Command{
		Use: "stackwhere",
	}

	pFlags := c.PersistentFlags()
	pFlags.BoolP(jsonFlagName, "j", false, "Output in JSON format")
	pFlags.StringArrayP(dwarvesFlagName, "D", nil, "Explicit DWARF files(s)")

	const primaryGroupID = "primary"
	c.AddGroup(
		&cobra.Group{
			ID:    primaryGroupID,
			Title: "Available Commands:",
		},
	)

	listCmd := listCommand()
	listCmd.GroupID = primaryGroupID

	lifetimes := lifetimesCommand()
	lifetimes.GroupID = primaryGroupID

	web := webCommand()
	web.GroupID = primaryGroupID

	c.AddCommand(
		listCmd,
		lifetimes,
		web,
		versionCommand(),
	)

	return c
}
