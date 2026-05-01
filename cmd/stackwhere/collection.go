package main

import (
	"fmt"
	"maps"
	"slices"

	"github.com/cilium/stackwhere/internal/dwarf"
	"github.com/spf13/cobra"
)

func collectionStackListCommand() *cobra.Command {
	c := &cobra.Command{
		Use:     "collection {collection}",
		Aliases: []string{"coll", "c"},
		Short:   "Prints the stack usage for each program in a collection.",
		Long:    "Prints the stack usage for each program in a given collection.",
		Example: "stackwhere collection /path/to/collection.o",
		Args:    cobra.ExactArgs(1),
		RunE:    (&collectionStackList{}).runE,
	}

	return c
}

type collectionStackList struct{}

func (csl *collectionStackList) runE(cmd *cobra.Command, args []string) error {
	collectionPath := args[0]

	tree, err := dwarf.NewDWARFTree(collectionPath)
	if err != nil {
		return fmt.Errorf("failed to parse DWARF data: %w", err)
	}

	stackUsagePerProgram := map[string]int64{}
	for _, prog := range tree.ByType(dwarf.TagSubprogram) {
		if !isBPFProgram(prog) {
			continue
		}

		stackUsagePerProgram[prog.Name()] = getProgramStackUsage(prog)
	}

	// Sort by stack usage, largest first, and then by name, and print.
	keys := slices.Collect(maps.Keys(stackUsagePerProgram))
	slices.SortFunc(keys, func(a, b string) int {
		return int(stackUsagePerProgram[b] - stackUsagePerProgram[a])
	})
	for _, prog := range keys {
		fmt.Printf("%3d bytes - %s\n", stackUsagePerProgram[prog], prog)
	}

	return nil
}

func getProgramStackUsage(prog *dwarf.Node) int64 {
	largestOffset := int64(0)
	lastSize := int64(0)
	dwarf.VisitPrefixOrder(prog, func(n *dwarf.Node) {
		// Only consider variables and function parameters since those are the things that can be stored on the stack.
		if n.Entry().Tag != dwarf.TagVariable && n.Entry().Tag != dwarf.TagFormalParameter {
			return
		}

		// Find all stack offsets used by this variable.
		offsets := stackOffsets(n)
		if len(offsets) == 0 {
			return
		}

		// If this was the largest stack offset we've seen so far, then the total stack usage must be at least
		// large enough to fit this variable. If this variable has the same largest offset as a previous variable,
		// but is larger than that previous variable, then the total stack usage must be increased to fit this variable.
		sz := n.ByteSize()
		for _, offset := range offsets {
			if offset > largestOffset {
				largestOffset = offset
				lastSize = sz
			}
			if offset == largestOffset && sz > lastSize {
				lastSize = sz
			}
		}
	})

	// Stack usage is always a multiple of 8 bytes, so round up to the nearest multiple of 8.
	stackUsage := largestOffset + lastSize
	if stackUsage%8 != 0 {
		stackUsage = ((stackUsage / 8) + 1) * 8
	}

	return stackUsage
}

func isBPFProgram(n *dwarf.Node) bool {
	if n.Entry().Tag != dwarf.TagSubprogram {
		return false
	}

	if n.Entry().Val(dwarf.AttrName) == nil {
		return false
	}

	if n.Entry().Val(dwarf.AttrInline) != nil {
		return false
	}

	if n.Entry().Val(dwarf.AttrType) == nil {
		return false
	}

	return true
}
