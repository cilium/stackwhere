package main

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/cilium/stackwhere/internal/stackview"
	"github.com/spf13/cobra"
)

func listCommand() *cobra.Command {
	c := &cobra.Command{
		Use:     "list {collection} [program]",
		Aliases: []string{"l"},
		Short:   "Prints the stack usage of all programs, or the stack listing of a specific program.",
		Long:    "Prints the stack usage of all programs, or the stack listing of a specific program.",
		Example: "stackwhere list /path/to/collection.o my_program",
		Args:    cobra.RangeArgs(1, 2),
	}

	flags := c.Flags()
	psl := &programStackList{
		flagCallStack: flags.BoolP("call-stack", "", false, "Show the full callstack of a variable"),
	}
	c.RunE = psl.runE

	return c
}

type programStackList struct {
	flagCallStack *bool
}

func (psl *programStackList) runE(cmd *cobra.Command, args []string) error {
	if len(args) == 1 {
		return psl.runListCollection(cmd, args)
	}

	return psl.runListProgram(cmd, args)
}

func (psl *programStackList) runListProgram(cmd *cobra.Command, args []string) error {
	collectionPath := args[0]
	functionName := args[1]

	analyzer, err := stackview.NewAnalyzer(collectionPath, dwarves(cmd))
	if err != nil {
		return err
	}

	usage, err := analyzer.ProgramDetails(functionName)
	if err != nil {
		return err
	}

	if jsonOutput(cmd) {
		e := json.NewEncoder(cmd.OutOrStdout())
		e.SetIndent("", "  ")
		if err := e.Encode(usage); err != nil {
			return fmt.Errorf("failed to encode stack usage data to JSON: %w", err)
		}
		return nil
	}

	w := cmd.OutOrStdout()
	if len(usage) == 0 {
		_, err := fmt.Fprintln(w, "No stack usage.")
		return err
	}

	for _, slots := range usage {
		if !*psl.flagCallStack {
			slots = slices.CompactFunc(slices.Clone(slots), func(a, b stackview.SlotUsage) bool {
				return a.DisplayEqual(b)
			})
		}

		if _, err := fmt.Fprintf(w, "R10-%d:\n", slots[0].Offset); err != nil {
			return err
		}
		for _, slot := range slots {
			size := fmt.Sprintf("%d", slot.ByteSize)
			if slot.ByteSize == -1 {
				size = "?"
			}

			name := slot.Name
			if name == "" {
				name = "(unknown)"
			}

			if _, err := fmt.Fprintf(w, "  %s - %s @ %s\n", size, name, slot.FileLineCol); err != nil {
				return err
			}
			if *psl.flagCallStack {
				for _, entry := range slot.Callstack {
					if _, err := fmt.Fprintf(w, "    %s @ %s\n", entry.Name, entry.FileLineCol); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func (psl *programStackList) runListCollection(cmd *cobra.Command, args []string) error {
	collectionPath := args[0]

	analyzer, err := stackview.NewAnalyzer(collectionPath, dwarves(cmd))
	if err != nil {
		return err
	}

	out, err := analyzer.CollectionSummaryInCollection()
	if err != nil {
		return err
	}

	if jsonOutput(cmd) {
		e := json.NewEncoder(cmd.OutOrStdout())
		e.SetIndent("", "  ")
		if err := e.Encode(out); err != nil {
			return fmt.Errorf("failed to encode stack usage data to JSON: %w", err)
		}
		return nil
	}

	w := cmd.OutOrStdout()
	for _, prog := range out {
		if _, err := fmt.Fprintf(w, "%3d bytes - %s\n", prog.StackUsage, prog.Name); err != nil {
			return err
		}
	}

	return nil
}
