// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stackview

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	dbgdwarf "github.com/cilium/stackwhere/internal/dwarf"
	"github.com/cilium/stackwhere/internal/dwarf/op"
)

// ErrFunctionNotFoundInCollection indicates a function was present in DWARF but not in the eBPF collection spec.
var ErrFunctionNotFoundInCollection = errors.New("function not found in eBPF collection")

// Analyzer provides stack usage information for one collection file.
type Analyzer struct {
	collectionPath string
	tree           *dbgdwarf.Tree
	functions      map[string]bpfFn
}

type bpfFn struct {
	fn    *btf.Func
	insns asm.Instructions
}

// ProgramStackUsage holds peak stack usage for one program.
type ProgramStackUsage struct {
	Name       string `json:"name"`
	StackUsage int64  `json:"stack_usage"`
}

// CallStackEntry describes one call frame for a stack slot.
type CallStackEntry struct {
	Name        string `json:"name"`
	FileLineCol string `json:"file_line_col"`
}

// SlotUsage describes one variable/register use mapped to a stack offset.
type SlotUsage struct {
	Offset      int64            `json:"offset"`
	Name        string           `json:"name"`
	ByteSize    int64            `json:"byte_size"`
	FileLineCol string           `json:"file_line_col"`
	Callstack   []CallStackEntry `json:"callstack,omitempty"`
}

func (s SlotUsage) displayEqual(other SlotUsage) bool {
	return s.Name == other.Name && s.ByteSize == other.ByteSize && s.FileLineCol == other.FileLineCol
}

// DisplayEqual reports whether two entries render as the same line in non-callstack views.
func (s SlotUsage) DisplayEqual(other SlotUsage) bool {
	return s.displayEqual(other)
}

type slotList [][]SlotUsage

func (s slotList) Add(slot SlotUsage) slotList {
	i, found := slices.BinarySearchFunc(s, []SlotUsage{slot}, func(a, b []SlotUsage) int {
		return cmp.Compare(a[0].Offset, b[0].Offset)
	})
	if found {
		s[i] = append(s[i], slot)
	} else {
		s = slices.Insert(s, i, []SlotUsage{slot})
	}
	return s
}

// NewAnalyzer parses DWARF data from a collection path.
func NewAnalyzer(collectionPath string) (*Analyzer, error) {
	tree, err := dbgdwarf.NewDWARFTree(collectionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DWARF data: %w", err)
	}

	return &Analyzer{
		collectionPath: collectionPath,
		tree:           tree,
	}, nil
}

// CollectionSummary returns peak stack usage for all BPF programs in the collection.
func (a *Analyzer) CollectionSummary() []ProgramStackUsage {
	stackUsagePerProgram := map[string]int64{}
	for _, prog := range a.tree.ByType(dbgdwarf.TagSubprogram) {
		if !isBPFProgram(prog) {
			continue
		}

		stackUsagePerProgram[prog.Name()] = getProgramStackUsage(prog)
	}

	return SortProgramStackUsage(stackUsagePerProgram)
}

// CollectionSummaryInCollection returns peak stack usage for BPF programs that
// are also present in the loaded eBPF collection.
func (a *Analyzer) CollectionSummaryInCollection() ([]ProgramStackUsage, error) {
	if err := a.loadFunctions(); err != nil {
		return nil, err
	}

	summary := a.CollectionSummary()
	stackUsagePerProgram := make(map[string]int64, len(summary))
	subProgsDwarf := a.tree.ByType(dbgdwarf.TagSubprogram)
	for _, prog := range summary {
		fn, ok := a.functions[prog.Name]
		if !ok || fn.fn == nil {
			continue
		}

		subProgDwarfIdx := slices.IndexFunc(subProgsDwarf, func(n *dbgdwarf.Node) bool {
			return n.Name() == prog.Name
		})
		if subProgDwarfIdx != -1 {
			inferredUsage := max(
				stackUsageFromSlots(stackSlotsFromInsns(fn, subProgsDwarf[subProgDwarfIdx])),
				stackUsageFromDirectMemoryAccesses(fn.insns),
			)
			prog.StackUsage = max(prog.StackUsage, inferredUsage)
		}

		stackUsagePerProgram[prog.Name] = prog.StackUsage
	}

	return SortProgramStackUsage(stackUsagePerProgram), nil
}

func stackUsageFromSlots(slots slotList) int64 {
	var largestOffset int64
	for _, group := range slots {
		for _, slot := range group {
			largestOffset = max(largestOffset, slot.Offset)
		}
	}

	return roundStackUsage(largestOffset)
}

func stackUsageFromDirectMemoryAccesses(insns asm.Instructions) int64 {
	var largestOffset int64
	for _, ins := range insns {
		if ins.Offset >= 0 {
			continue
		}

		class := ins.OpCode.Class()
		mode := ins.OpCode.Mode()
		isStackLoad := class == asm.LdXClass &&
			(mode == asm.MemMode || mode == asm.MemSXMode) && ins.Src == asm.R10
		isStackStore := (class == asm.StClass || class == asm.StXClass) &&
			mode == asm.MemMode && ins.Dst == asm.R10
		if isStackLoad || isStackStore {
			largestOffset = max(largestOffset, -int64(ins.Offset))
		}
	}

	return roundStackUsage(largestOffset)
}

func roundStackUsage(usage int64) int64 {
	if usage%8 != 0 {
		usage = ((usage / 8) + 1) * 8
	}
	return usage
}

// ProgramDetails returns grouped stack slot usage for a single program.
func (a *Analyzer) ProgramDetails(functionName string) ([][]SlotUsage, error) {
	if err := a.loadFunctions(); err != nil {
		return nil, err
	}

	subProgsDwarf := a.tree.ByType(dbgdwarf.TagSubprogram)
	subProgDwarfIdx := slices.IndexFunc(subProgsDwarf, func(n *dbgdwarf.Node) bool {
		return n.Name() == functionName
	})
	if subProgDwarfIdx == -1 {
		return nil, fmt.Errorf("function %q not found in DWARF data", functionName)
	}

	subProgDwarf := subProgsDwarf[subProgDwarfIdx]
	subProg := a.functions[functionName]
	if subProg.fn == nil {
		return nil, fmt.Errorf("%w: %q", ErrFunctionNotFoundInCollection, functionName)
	}

	usage := stackSlotsFromDWARFVars(subProgDwarf)
	usage = append(usage, stackSlotsFromInsns(subProg, subProgDwarf)...)
	usage = normalizeSlotUsage(usage)

	return usage, nil
}

func (a *Analyzer) loadFunctions() error {
	if a.functions != nil {
		return nil
	}

	coll, err := ebpf.LoadCollectionSpec(a.collectionPath)
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

	a.functions = fns
	return nil
}

func normalizeSlotUsage(usage slotList) slotList {
	// Sort outer array by offset.
	slices.SortFunc(usage, func(a, b []SlotUsage) int {
		return cmp.Compare(a[0].Offset, b[0].Offset)
	})

	// Merge inner arrays with the same offset.
	for i := range slices.Backward(usage) {
		if i == 0 {
			break
		}

		if usage[i][0].Offset == usage[i-1][0].Offset {
			usage[i-1] = append(usage[i-1], usage[i]...)
			usage = slices.Delete(usage, i, i+1)
		}
	}

	// Sort inner arrays by size (largest first), name, then source location; and dedupe full entries.
	for i := range usage {
		slices.SortFunc(usage[i], func(a, b SlotUsage) int {
			sz := cmp.Compare(b.ByteSize, a.ByteSize)
			if sz != 0 {
				return sz
			}

			name := strings.Compare(a.Name, b.Name)
			if name != 0 {
				return name
			}

			return strings.Compare(a.FileLineCol, b.FileLineCol)
		})

		usage[i] = slices.CompactFunc(usage[i], slotUsageEqual)
	}

	return usage
}

func slotUsageEqual(a, b SlotUsage) bool {
	return a.Name == b.Name && a.ByteSize == b.ByteSize && a.FileLineCol == b.FileLineCol && slices.Equal(a.Callstack, b.Callstack)
}

// SortProgramStackUsage returns usage sorted by bytes descending and name ascending.
func SortProgramStackUsage(stackUsagePerProgram map[string]int64) []ProgramStackUsage {
	out := make([]ProgramStackUsage, 0, len(stackUsagePerProgram))
	for _, prog := range slices.Collect(maps.Keys(stackUsagePerProgram)) {
		out = append(out, ProgramStackUsage{
			Name:       prog,
			StackUsage: stackUsagePerProgram[prog],
		})
	}

	slices.SortFunc(out, func(a, b ProgramStackUsage) int {
		sz := cmp.Compare(b.StackUsage, a.StackUsage)
		if sz != 0 {
			return sz
		}

		return strings.Compare(a.Name, b.Name)
	})

	return out
}

func getProgramStackUsage(prog *dbgdwarf.Node) int64 {
	largestOffset := int64(0)
	lastSize := int64(0)
	dbgdwarf.VisitPrefixOrder(prog, func(n *dbgdwarf.Node) {
		if n.Entry().Tag != dbgdwarf.TagVariable && n.Entry().Tag != dbgdwarf.TagFormalParameter {
			return
		}

		offsets := stackOffsets(n)
		if len(offsets) == 0 {
			return
		}

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

	stackUsage := largestOffset + lastSize
	if stackUsage%8 != 0 {
		stackUsage = ((stackUsage / 8) + 1) * 8
	}

	return stackUsage
}

func isBPFProgram(n *dbgdwarf.Node) bool {
	if n.Entry().Tag != dbgdwarf.TagSubprogram {
		return false
	}

	if n.Entry().Val(dbgdwarf.AttrName) == nil {
		return false
	}

	if n.Entry().Val(dbgdwarf.AttrInline) != nil {
		return false
	}

	// Concrete functions have an address or ranges. Unlike declarations, void
	// functions have executable code but no return type attribute.
	if n.Entry().Val(dbgdwarf.AttrLowpc) == nil && n.Entry().Val(dbgdwarf.AttrRanges) == nil {
		return false
	}

	return true
}

func stackSlotsFromDWARFVars(progDwarf *dbgdwarf.Node) slotList {
	result := slotList{}

	stackMap := map[int64][]*dbgdwarf.Node{}
	dbgdwarf.VisitPrefixOrder(progDwarf, func(n *dbgdwarf.Node) {
		if n.Entry().Tag != dbgdwarf.TagVariable && n.Entry().Tag != dbgdwarf.TagFormalParameter {
			return
		}

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
		slices.SortFunc(nodes, func(a, b *dbgdwarf.Node) int {
			sz := cmp.Compare(b.ByteSize(), a.ByteSize())
			if sz != 0 {
				return sz
			}

			return strings.Compare(a.Name(), b.Name())
		})

		for _, n := range nodes {
			callstack := []CallStackEntry{}

			parents := []*dbgdwarf.Node{}
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

				callstack = append(callstack, CallStackEntry{
					Name:        parent.Name(),
					FileLineCol: fileLineCol,
				})
			}

			fileLineCol := n.CallFileLineCol()
			if fileLineCol == "" {
				fileLineCol = n.FileLineCol()
			}

			usage := SlotUsage{
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

func stackOffsets(n *dbgdwarf.Node) []int64 {
	offsets := []int64{}

	if location, err := n.Location(); err == nil && location != nil {
		for _, locOp := range location {
			if locOp.Opcode == op.DW_OP_fbreg {
				if !slices.Contains(offsets, locOp.Args[0].(int64)) {
					offsets = append(offsets, locOp.Args[0].(int64))
				}
			}
		}
	} else if locList, err := n.LocationList(); err == nil && locList != nil {
		for _, entry := range locList.Entries() {
			switch e := entry.(type) {
			case dbgdwarf.LLEOffsetPair:
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

// Find stack slot usage by looking at the instructions and enhance with DWARF information.
func stackSlotsFromInsns(fn bpfFn, progDbg *dbgdwarf.Node) slotList {
	i2n := instructionToNodes(progDbg)

	var result slotList

	iter := fn.insns.Iterate()
	for iter.Next() {
		if iter.Ins.Src == asm.R10 && iter.Ins.OpCode.ALUOp() == asm.Mov {
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

			usage := SlotUsage{
				Offset:      -nextInsn.Constant,
				Name:        iter.Ins.Dst.String(),
				ByteSize:    -1,
				FileLineCol: fileCol,
			}
			for _, n := range i2n[byteOff] {
				if n.Name() == "" && n.FileLineCol() == "" {
					continue
				}

				fileLineCol := n.CallFileLineCol()
				if fileLineCol == "" {
					fileLineCol = n.FileLineCol()
				}

				usage.Callstack = append(usage.Callstack, CallStackEntry{
					Name:        n.Name(),
					FileLineCol: fileLineCol,
				})
			}

			result = result.Add(usage)
		}
	}

	return result
}

func instructionToNodes(prog *dbgdwarf.Node) map[uint64][]*dbgdwarf.Node {
	instRange := make(map[uint64][]*dbgdwarf.Node)

	progInsOffset := prog.Entry().Val(dbgdwarf.AttrLowpc).(uint64)

	dbgdwarf.VisitPrefixOrder(prog, func(n *dbgdwarf.Node) {
		lowpc := n.Entry().Val(dbgdwarf.AttrLowpc)
		highpc := n.Entry().Val(dbgdwarf.AttrHighpc)
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

	for _, nodes := range instRange {
		slices.Reverse(nodes)
	}

	return instRange
}
