package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/stackwhere/internal/dwarf"
	"github.com/cilium/stackwhere/internal/dwarf/op"
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

	tree, err := dwarf.NewDWARFTree(collectionPath)
	if err != nil {
		return fmt.Errorf("failed to parse DWARF data: %w", err)
	}

	usage := getStackSlotUsage(tree, functionName)
	for _, slots := range usage {
		fmt.Printf("R10-%d:\n", slots[0].offset)
		for _, slot := range slots {
			fmt.Printf("  %d - %s @ %s\n", slot.byteSize, slot.name, slot.fileCol)
			if *psl.flagCallStack {
				for _, entry := range slot.callstack {
					fmt.Printf("    %s @ %s\n", entry.name, entry.fileCol)
				}
			}
		}
	}

	return nil
}

type slotUsage struct {
	offset    int64
	name      string
	byteSize  int64
	fileCol   string
	callstack []callStackEntry
}

type callStackEntry struct {
	name    string
	fileCol string
}

// getStackSlotUsage returns a list of stack slots used by the given function, sorted by their offset from R10 (largest offset first).
// Each stack slot includes the variables that live at that slot, sorted by byte size (largest first) and then name,
// and optionally the callstack of each variable.
func getStackSlotUsage(tree *dwarf.Tree, functionName string) [][]slotUsage {
	result := [][]slotUsage{}
	for _, n := range tree.ByType(dwarf.TagSubprogram) {
		name := n.Name()
		if name == "" || name != functionName {
			continue
		}

		entrypoint := n
		stackMap := map[int64][]*dwarf.Node{}
		dwarf.VisitPrefixOrder(n, func(n *dwarf.Node) {
			// We are interested in variables and function parameters since those are the things that can be stored on
			// the stack.
			if n.Entry().Tag != dwarf.TagVariable && n.Entry().Tag != dwarf.TagFormalParameter {
				return
			}

			// If the current variable lives on the stack, add it to the map of stack offsets to variables that live at that offset.
			offsets := stackOffsets(n)
			if len(offsets) > 0 {
				for _, offset := range offsets {
					if !slices.Contains(stackMap[offset], n) {
						stackMap[offset] = append(stackMap[offset], n)
					}
				}
			}
		})

		// Print the variables grouped by their stack offset, sorted by largest byte size first and then name.
		for _, offset := range slices.SortedFunc(maps.Keys(stackMap), func(a, b int64) int {
			return int(b - a)
		}) {
			nodes := stackMap[offset]
			slices.SortFunc(nodes, func(a, b *dwarf.Node) int {
				sz := int(b.ByteSize()) - int(a.ByteSize())
				if sz != 0 {
					return sz
				}

				return strings.Compare(a.Name(), b.Name())
			})

			// Remove duplicates that can occur, for example when a function is inlined multiple times and it
			// ends up reusing the same stack space.
			nodes = slices.CompactFunc(nodes, func(a, b *dwarf.Node) bool {
				return a.Name() == b.Name() && a.ByteSize() == b.ByteSize() && a.FileCol() == b.FileCol()
			})
			for _, n := range nodes {
				callstack := []callStackEntry{}

				parents := []*dwarf.Node{}
				p := n
				for p != nil {
					p = p.Parent()
					parents = append(parents, p)
					if p == entrypoint {
						break
					}
				}
				for _, parent := range parents {
					if parent.Name() == "" {
						continue
					}
					callstack = append(callstack, callStackEntry{
						name:    parent.Name(),
						fileCol: parent.FileCol(),
					})
				}

				usage := []slotUsage{{
					offset:    offset,
					name:      n.Name(),
					byteSize:  n.ByteSize(),
					fileCol:   n.FileCol(),
					callstack: callstack,
				}}

				i, found := slices.BinarySearchFunc(result, usage, func(a, b []slotUsage) int {
					return int(a[0].offset - b[0].offset)
				})
				if found {
					result[i] = append(result[i], usage...)
				} else {
					result = slices.Insert(result, i, usage)
				}
			}
		}
	}

	return result
}

func stackOffsets(n *dwarf.Node) []int64 {
	offsets := []int64{}

	// DWARF can express variable locations in two ways: as a single location expression or
	// as a list of location expressions that are valid for different ranges of instructions.
	if location, err := n.Location(); err == nil && location != nil {
		// Loop over all instructions, see if any of them reference the frame base register, and thus some
		// offset into the stack.
		for _, locOp := range location {
			if locOp.Opcode == op.DW_OP_fbreg {
				if !slices.Contains(offsets, locOp.Args[0].(int64)) {
					offsets = append(offsets, locOp.Args[0].(int64))
				}
			}
		}
	} else if locList, err := n.LocationList(); err == nil && locList != nil {
		// Loop over all entries in the locations list, each entry is valid for a specific range of instructions
		// so a single variable may live in different places (registers, stack, etc) at different points in
		// the program.
		for _, entry := range locList.Entries() {
			// The base address + offset pair entries seem to be the only ones used in BPF object files.
			switch e := entry.(type) {
			case dwarf.LLEOffsetPair:
				// Loop over all instructions, see if any of them reference the frame base register, and thus some
				// offset into the stack.
				for _, locOp := range e.Ops() {
					if locOp.Opcode == op.DW_OP_fbreg || locOp.Opcode == op.DW_OP_breg10 {
						if !slices.Contains(offsets, locOp.Args[0].(int64)) {
							offsets = append(offsets, locOp.Args[0].(int64))
						}
					}
				}
			}
		}
	}

	slices.Sort(offsets)
	return slices.Compact(offsets)
}

func (psl *programStackList) runListCollection(cmd *cobra.Command, args []string) error {
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
