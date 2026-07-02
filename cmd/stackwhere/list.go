package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
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

type bpfFn struct {
	fn    *btf.Func
	insns asm.Instructions
}

func (psl *programStackList) runListProgram(cmd *cobra.Command, args []string) error {
	collectionPath := args[0]
	functionName := args[1]

	tree, err := dwarf.NewDWARFTree(collectionPath)
	if err != nil {
		return fmt.Errorf("failed to parse DWARF data: %w", err)
	}

	coll, err := ebpf.LoadCollectionSpec(collectionPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection: %w", err)
	}

	fns := make(map[string]bpfFn)
	for _, prog := range coll.Programs {
		var cur bpfFn
		iter := prog.Instructions.Iterate()
		for iter.Next() {
			if fn := btf.FuncMetadata(iter.Ins); fn != nil {
				if cur.fn != nil {
					fns[cur.fn.Name] = cur
				}

				cur.fn = fn
				cur.insns = asm.Instructions{}
			}

			cur.insns = append(cur.insns, *iter.Ins)
		}

		if cur.fn != nil {
			fns[cur.fn.Name] = cur
		}
	}

	subProgsDwarf := tree.ByType(dwarf.TagSubprogram)
	subProgDwarfIdx := slices.IndexFunc(subProgsDwarf, func(n *dwarf.Node) bool {
		return n.Name() == functionName
	})
	if subProgDwarfIdx == -1 {
		return fmt.Errorf("function %q not found in DWARF data", functionName)
	}

	subProgDwarf := subProgsDwarf[subProgDwarfIdx]
	subProg := fns[functionName]
	if subProg.fn == nil {
		return fmt.Errorf("function %q not found in eBPF collection", functionName)
	}

	usage := stackSlotsFromDWARFVars(subProgDwarf)
	usage = append(usage, stackSlotsFromInsns(subProg, subProgDwarf)...)

	// Sort outer array
	slices.SortFunc(usage, func(a, b []slotUsage) int {
		return int(a[0].Offset - b[0].Offset)
	})
	// Merge inner arrays with the same offset
	for i := range slices.Backward(usage) {
		if i == 0 {
			break
		}

		if usage[i][0].Offset == usage[i-1][0].Offset {
			usage[i-1] = append(usage[i-1], usage[i]...)
			usage = slices.Delete(usage, i, i+1)
		}
	}
	// Sort inner arrays by size, largest first, and then by name. And deduplicate.
	for i := range usage {
		slices.SortFunc(usage[i], func(a, b slotUsage) int {
			sz := int(b.ByteSize - a.ByteSize)
			if sz != 0 {
				return sz
			}

			name := strings.Compare(a.Name, b.Name)
			if name != 0 {
				return name
			}

			return strings.Compare(a.FileLineCol, b.FileLineCol)
		})

		// Remove duplicates that can occur, for example when a function is inlined multiple times and it ends up reusing the same stack space.
		usage[i] = slices.CompactFunc(usage[i], func(a, b slotUsage) bool {
			callstackEqual := true
			if len(a.Callstack) != len(b.Callstack) {
				callstackEqual = false
			} else {
				for j := range a.Callstack {
					if a.Callstack[j] != b.Callstack[j] {
						callstackEqual = false
						break
					}
				}
			}
			return a.Name == b.Name && a.ByteSize == b.ByteSize && a.FileLineCol == b.FileLineCol && callstackEqual
		})
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
	for _, slots := range usage {
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

type slotList [][]slotUsage

func (s slotList) Add(slot slotUsage) slotList {
	i, found := slices.BinarySearchFunc(s, []slotUsage{slot}, func(a, b []slotUsage) int {
		return int(a[0].Offset - b[0].Offset)
	})
	if found {
		s[i] = append(s[i], slot)
	} else {
		s = slices.Insert(s, i, []slotUsage{slot})
	}
	return s
}

type slotUsage struct {
	Offset      int64            `json:"offset"`
	Name        string           `json:"name"`
	ByteSize    int64            `json:"byte_size"`
	FileLineCol string           `json:"file_line_col"`
	Callstack   []callStackEntry `json:"callstack,omitempty"`
}

type callStackEntry struct {
	Name        string `json:"name"`
	FileLineCol string `json:"file_line_col"`
}

// stackSlotsFromDWARFVars returns a list of stack slots used by the given function, result is unsorted.
func stackSlotsFromDWARFVars(progDwarf *dwarf.Node) slotList {
	result := slotList{}

	stackMap := map[int64][]*dwarf.Node{}
	dwarf.VisitPrefixOrder(progDwarf, func(n *dwarf.Node) {
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

	for offset, nodes := range stackMap {
		slices.SortFunc(nodes, func(a, b *dwarf.Node) int {
			sz := int(b.ByteSize()) - int(a.ByteSize())
			if sz != 0 {
				return sz
			}

			return strings.Compare(a.Name(), b.Name())
		})

		for _, n := range nodes {
			callstack := []callStackEntry{}

			parents := []*dwarf.Node{}
			p := n
			for p != nil {
				p = p.Parent()
				parents = append(parents, p)
				if p == progDwarf {
					break
				}
			}
			for _, parent := range parents {
				if parent.Name() == "" {
					continue
				}
				fileLineCol := parent.CallFileLineCol()
				if fileLineCol == "" {
					fileLineCol = parent.FileLineCol()
				}

				callstack = append(callstack, callStackEntry{
					Name:        parent.Name(),
					FileLineCol: fileLineCol,
				})
			}

			fileLineCol := n.CallFileLineCol()
			if fileLineCol == "" {
				fileLineCol = n.FileLineCol()
			}

			usage := slotUsage{
				Offset:      offset,
				Name:        n.Name(),
				ByteSize:    n.ByteSize(),
				FileLineCol: fileLineCol,
				Callstack:   callstack,
			}

			result = result.Add(usage)
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

	out := sortedProgramStackUsage(stackUsagePerProgram)

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

type programStackUsage struct {
	Name       string `json:"name"`
	StackUsage int64  `json:"stack_usage"`
}

func sortedProgramStackUsage(stackUsagePerProgram map[string]int64) []programStackUsage {
	out := make([]programStackUsage, 0, len(stackUsagePerProgram))
	for _, prog := range slices.Collect(maps.Keys(stackUsagePerProgram)) {
		out = append(out, programStackUsage{
			Name:       prog,
			StackUsage: stackUsagePerProgram[prog],
		})
	}

	// Sort by stack usage, largest first, and then by name.
	slices.SortFunc(out, func(a, b programStackUsage) int {
		sz := int(b.StackUsage - a.StackUsage)
		if sz != 0 {
			return sz
		}

		return strings.Compare(a.Name, b.Name)
	})

	return out
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

// Find stack slot usage by looking at the instructions and enhance with DWARF information.
// We are specifically looking for this pattern of instructions:
//
//	Mov Rx, R10
//	Add Rx, -N
//
// Where Rx is any register and N is some constant.
func stackSlotsFromInsns(fn bpfFn, progDbg *dwarf.Node) slotList {
	i2n := instructionToNodes(progDbg)

	var result slotList

	iter := fn.insns.Iterate()
	for iter.Next() {
		if iter.Ins.Src == asm.R10 && iter.Ins.OpCode.ALUOp() == asm.Mov {
			// Validate the pattern: Mov Rx, R10 followed by Add Rx, -N on the same register.
			nextIdx := iter.Index + 1
			if nextIdx >= len(fn.insns) {
				continue
			}
			nextInsn := fn.insns[nextIdx]
			if nextInsn.OpCode.ALUOp() != asm.Add || nextInsn.Dst != iter.Ins.Dst || nextInsn.Constant >= 0 {
				continue
			}

			byteOff := uint64(iter.Offset * asm.InstructionSize)

			var line *btf.Line
			for j := iter.Index; j < len(fn.insns); j++ {
				ins := fn.insns[j]
				if lo, ok := ins.Source().(*btf.Line); ok && lo.LineNumber() != 0 {
					line = lo
					break
				}
			}

			fileCol := ""
			if line != nil {
				fileCol = line.FileName() + ":" + fmt.Sprint(line.LineNumber())
			}

			usage := slotUsage{
				Offset:      -nextInsn.Constant,
				Name:        iter.Ins.Dst.String(),
				ByteSize:    -1,
				FileLineCol: fileCol,
			}
			for _, n := range i2n[byteOff] {
				// Some nodes like Lexical blocks do not have a name or file/line information.
				// So not useful in the trace.
				if n.Name() == "" && n.FileLineCol() == "" {
					continue
				}

				fileLineCol := n.CallFileLineCol()
				if fileLineCol == "" {
					fileLineCol = n.FileLineCol()
				}

				usage.Callstack = append(usage.Callstack, callStackEntry{
					Name:        n.Name(),
					FileLineCol: fileLineCol,
				})
			}

			result = result.Add(usage)
		}
	}

	return result
}

// Create a mapping of instruction offsets to the DWARF nodes that are valid at that instruction.
func instructionToNodes(prog *dwarf.Node) map[uint64][]*dwarf.Node {
	instRange := make(map[uint64][]*dwarf.Node)

	progInsOffset := prog.Entry().Val(dwarf.AttrLowpc).(uint64)

	dwarf.VisitPrefixOrder(prog, func(n *dwarf.Node) {
		lowpc := n.Entry().Val(dwarf.AttrLowpc)
		highpc := n.Entry().Val(dwarf.AttrHighpc)
		if lowpc != nil && highpc != nil {
			for i := lowpc.(uint64); i < lowpc.(uint64)+uint64(highpc.(int64)); i += asm.InstructionSize {
				instRange[i-progInsOffset] = append(instRange[i-progInsOffset], n)
			}
		}

		if rng, err := n.Ranges(); err == nil {
			for _, r := range rng.Ranges {
				for i := r.Start; i < r.End; i += asm.InstructionSize {
					instRange[i-progInsOffset] = append(instRange[i-progInsOffset], n)
				}
			}
		}
	})

	// Reverse since we want to report the stack callstack from the innermost function to the outermost
	for _, nodes := range instRange {
		slices.Reverse(nodes)
	}

	return instRange
}
