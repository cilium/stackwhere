package main

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/stackwhere/internal/analyze"
	"github.com/spf13/cobra"
)

func lifetimesCommand() *cobra.Command {
	c := &cobra.Command{
		Use:     "lifetimes {collection} {program} {svg output}",
		Aliases: []string{"lt"},
		Short:   "Prints stack-slot lifetimes for a program.",
		Long:    "Prints stack-slot lifetimes for a program.",
		Example: "stackwhere lifetimes /path/to/collection.o my_program output.svg",
		Args:    cobra.ExactArgs(3),
	}

	lc := lifetimesCmd{}

	flags := c.Flags()
	lc.debug = flags.Bool("debug", false, "Print debugging information")
	lc.dumpInstructions = flags.Bool("dump-instructions", false, "Dump instructions")
	lc.dumpLifetimes = flags.Bool("dump-lifetimes", false, "Dump lifetimes")
	lc.drawBBB = flags.Bool("draw-bbb", false, "Draw basic block boundaries in the output")

	c.RunE = lc.run
	return c
}

type Lifetime struct {
	Intervals []LifetimeInterval
}

func (lt *Lifetime) Add(it LifetimeInterval) {
	idx, found := slices.BinarySearchFunc(lt.Intervals, it, func(a, b LifetimeInterval) int {
		return cmp.Compare(a.Start, b.Start)
	})
	if found {
		existing := lt.Intervals[idx]
		if existing.End != it.End {
			lt.Intervals[idx].End = it.End
		}
		return
	}

	lt.Intervals = slices.Insert(lt.Intervals, idx, it)
}

func (lt Lifetime) String() string {
	var sb strings.Builder
	for i, it := range lt.Intervals {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(it.String())
	}

	return sb.String()
}

type LifetimeInterval struct {
	Start      asm.RawInstructionOffset
	End        asm.RawInstructionOffset
	BlockStart bool
}

func (it LifetimeInterval) String() string {
	var prefix string
	if it.BlockStart {
		prefix = "S"
	}
	return fmt.Sprintf("[%s%d; %d]", prefix, it.Start, it.End)
}

func LTInterval(start, end asm.RawInstructionOffset, blockStart bool) LifetimeInterval {
	return LifetimeInterval{Start: start, End: end, BlockStart: blockStart}
}

type state struct {
	regs            [11]regState
	stack           map[int16]stackState
	reachableWrites []rw
}

func (s state) copy() state {
	var copy state
	copy.regs = s.regs
	copy.stack = maps.Clone(s.stack)
	copy.reachableWrites = slices.Clone(s.reachableWrites)
	return copy
}

type regState struct {
	mapPtr *ebpf.MapSpec

	hasScalar bool
	scalar    int64

	fpPtr    bool
	fpSetOff asm.RawInstructionOffset
	fpOff    int16
}

type stackState struct {
	spilled regState
}

type StackLifetime struct {
	offset   int16
	lifetime *Lifetime
}

type bpfFn struct {
	fn    *btf.Func
	insns asm.Instructions
}

type lifetimesCmd struct {
	// Dump visitor state, reachable writes, reachable reads, and discovered lifetimes
	debug            *bool
	dumpInstructions *bool
	dumpLifetimes    *bool
	drawBBB          *bool
}

func loadCollectionFunctions(collectionPath string) (*ebpf.CollectionSpec, map[string]bpfFn, error) {
	spec, err := ebpf.LoadCollectionSpec(collectionPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load ebpf collection: %w", err)
	}

	fns := make(map[string]bpfFn)
	for _, prog := range spec.Programs {
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

	return spec, fns, nil
}

func computeStackLifetimes(blocks analyze.Blocks, insns asm.Instructions, reachableWrites map[*analyze.Block][]rw, reads []rw) []StackLifetime {
	var results []StackLifetime

	for _, read := range reads {
		lt := &Lifetime{}

		visited := make(map[*analyze.Block]bool)
		var visit func(block *analyze.Block, stack []*analyze.Block)
		visit = func(block *analyze.Block, stack []*analyze.Block) {
			if visited[block] {
				return
			}
			visited[block] = true

			var reachableWritesForOffset []rw
			for _, write := range reachableWrites[block] {
				if write.Offset == read.Offset {
					reachableWritesForOffset = append(reachableWritesForOffset, write)
				}
			}

			if len(reachableWritesForOffset) == 0 {
				return
			}

			var writesInCur []rw
			for _, write := range reachableWritesForOffset {
				if write.Block == block {
					writesInCur = append(writesInCur, write)
				}
			}
			slices.SortFunc(writesInCur, func(a, b rw) int {
				return cmp.Compare(a.RawIns, b.RawIns)
			})

			if len(writesInCur) > 0 {
				if block == read.Block {
					for _, write := range slices.Backward(writesInCur) {
						if write.RawIns < read.RawIns {
							lt.Add(LTInterval(write.RawIns, read.RawIns, false))
							return
						}
					}
				} else {
					lastWrite := writesInCur[len(writesInCur)-1]
					lt.Add(LTInterval(lastWrite.RawIns, insRawOff(block, insns, block.End), false))
					for _, b := range slices.Backward(stack) {
						lt.Add(LTInterval(b.Raw, insRawOff(b, insns, b.End), true))
					}
					lt.Add(LTInterval(read.Block.Raw, read.RawIns, true))
					return
				}
			}

			for _, pred := range block.Predecessors {
				visit(pred, append(stack, block))
			}
		}
		visit(read.Block, nil)

		if len(lt.Intervals) > 0 {
			results = append(results, StackLifetime{
				offset:   read.Offset,
				lifetime: lt,
			})
		}
	}

	slices.SortFunc(results, func(a, b StackLifetime) int {
		if a.offset == b.offset {
			return cmp.Compare(a.lifetime.Intervals[0].Start, b.lifetime.Intervals[0].Start)
		}

		return cmp.Compare(a.offset, b.offset)
	})

	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].offset != results[j].offset {
				break
			}

			overlaps := false
			for _, it1 := range results[i].lifetime.Intervals {
				for _, it2 := range results[j].lifetime.Intervals {
					if it1.Start <= it2.End && it2.Start <= it1.End {
						overlaps = true
						break
					}
				}
			}
			if overlaps {
				for _, it2 := range results[j].lifetime.Intervals {
					results[i].lifetime.Add(it2)
				}
				results = slices.Delete(results, j, j+1)
				j--
			}
		}
	}

	for _, slt := range results {
		for i := len(slt.lifetime.Intervals) - 1; i > 0; i-- {
			merge := slt.lifetime.Intervals[i-1].End == slt.lifetime.Intervals[i].Start
			if slt.lifetime.Intervals[i-1].End == slt.lifetime.Intervals[i].Start-1 && slt.lifetime.Intervals[i].BlockStart {
				merge = true
			}
			if merge {
				slt.lifetime.Intervals[i-1].End = slt.lifetime.Intervals[i].End
				slt.lifetime.Intervals = slices.Delete(slt.lifetime.Intervals, i, i+1)
			}
		}
	}

	return results
}

func buildProgramLifetimeGraph(spec *ebpf.CollectionSpec, insns asm.Instructions, drawBBB bool) (string, error) {
	if len(insns) == 0 {
		return "", nil
	}

	blocks, err := analyze.MakeBlocks(insns)
	if err != nil {
		return "", fmt.Errorf("make blocks: %w", err)
	}
	if len(blocks) == 0 {
		return "", nil
	}

	visitor := &visitor{
		dbgWriter:       io.Discard,
		spec:            spec,
		insns:           insns,
		reachableWrites: make(map[*analyze.Block][]rw),
		inStates:        make(map[*analyze.Block]state),
		outStates:       make(map[*analyze.Block]state),
		seenReads:       make(map[rw]struct{}),
		seenWrites:      make(map[rw]struct{}),
	}
	visitor.visit(blocks[0], state{stack: make(map[int16]stackState)})

	results := computeStackLifetimes(blocks, insns, visitor.reachableWrites, visitor.reads)
	return graphLifetimes(results, blocks, insns, visitor.writes, visitor.reads, drawBBB), nil
}

func (lc *lifetimesCmd) run(cmd *cobra.Command, args []string) error {
	dbgWriter := cmd.OutOrStdout()

	spec, fns, err := loadCollectionFunctions(args[0])
	if err != nil {
		return err
	}

	fn := fns[args[1]]
	if fn.fn == nil {
		return fmt.Errorf("program %s not found in collection", args[1])
	}

	blocks, err := analyze.MakeBlocks(fn.insns)
	if err != nil {
		return fmt.Errorf("make blocks: %w", err)
	}

	if *lc.dumpInstructions || *lc.debug {
		_, _ = fmt.Fprintln(dbgWriter, "=== Program instructions ===")
		_, _ = fmt.Fprint(dbgWriter, blocks.Dump(fn.insns))
	}

	visitor := &visitor{
		dbgWriter:       io.Discard,
		spec:            spec,
		insns:           fn.insns,
		reachableWrites: make(map[*analyze.Block][]rw),
		inStates:        make(map[*analyze.Block]state),
		outStates:       make(map[*analyze.Block]state),
		seenReads:       make(map[rw]struct{}),
		seenWrites:      make(map[rw]struct{}),
	}
	if *lc.debug {
		_, _ = fmt.Fprintln(dbgWriter, "=== Visitor state ===")
		visitor.dbgWriter = dbgWriter
	}
	visitor.visit(blocks[0], state{stack: make(map[int16]stackState)})

	if visitor.inaccurate {
		_, _ = fmt.Fprintln(dbgWriter, "WARN: analysis may be inaccurate due to unhandled instructions or unknown helper functions, see debug log for details")
	}

	if *lc.debug {
		_, _ = fmt.Fprintln(dbgWriter, "\n=== Reachable writes per block ===")
		for _, block := range blocks {
			_, _ = fmt.Fprintf(dbgWriter, "%d:\n", block.ID)
			for _, write := range visitor.reachableWrites[block] {
				_, _ = fmt.Fprintf(dbgWriter, "\tBlock: %d, Offset: %d, RawIns: %d\n", write.Block.ID, write.Offset, write.RawIns)
			}
		}

		_, _ = fmt.Fprintln(dbgWriter, "\n=== Reads in program ===")
		for _, read := range visitor.reads {
			_, _ = fmt.Fprintf(dbgWriter, "\tBlock: %d, Offset: %d, RawIns: %d\n", read.Block.ID, read.Offset, read.RawIns)
		}
	}

	results := computeStackLifetimes(blocks, fn.insns, visitor.reachableWrites, visitor.reads)
	if *lc.debug {
		_, _ = fmt.Fprintln(dbgWriter, "\n=== Lifetime discovery ===")
		for _, slt := range results {
			_, _ = fmt.Fprintf(dbgWriter, "%d : %v\n", slt.offset, slt.lifetime)
		}
	}

	if err := os.WriteFile(args[2], []byte(graphLifetimes(results, blocks, fn.insns, visitor.writes, visitor.reads, *lc.drawBBB)), 0644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	slices.SortFunc(results, func(sl1, sl2 StackLifetime) int {
		sl1LifetimeLen := 0
		for _, it := range sl1.lifetime.Intervals {
			sl1LifetimeLen += int(it.End - it.Start)
		}

		sl2LifetimeLen := 0
		for _, it := range sl2.lifetime.Intervals {
			sl2LifetimeLen += int(it.End - it.Start)
		}
		return cmp.Compare(sl2LifetimeLen, sl1LifetimeLen)
	})

	if *lc.dumpLifetimes || *lc.debug {
		_, _ = fmt.Fprintln(dbgWriter, "\n=== Lifetimes ===")
		lenPerOffset := make(map[int16]struct {
			offset      int16
			lifetimeLen int
		})
		for _, slt := range results {
			lifetimeLen := 0
			for _, it := range slt.lifetime.Intervals {
				lifetimeLen += int(it.End - it.Start)
			}
			offLen := lenPerOffset[slt.offset]
			offLen.offset = slt.offset
			offLen.lifetimeLen += lifetimeLen
			lenPerOffset[slt.offset] = offLen
			_, _ = fmt.Fprintf(dbgWriter, "%d: %d %s\n", slt.offset, lifetimeLen, slt.lifetime)
		}

		_, _ = fmt.Fprintln(dbgWriter, "\n=== Least packed offsets ===")
		for _, lifeLen := range slices.SortedFunc(maps.Values(lenPerOffset), func(a, b struct {
			offset      int16
			lifetimeLen int
		}) int {
			return cmp.Compare(a.lifetimeLen, b.lifetimeLen)
		}) {
			_, _ = fmt.Fprintf(dbgWriter, "%d: %d\n", lifeLen.offset, lifeLen.lifetimeLen)
		}
	}

	return nil
}

func insRawOff(block *analyze.Block, insns asm.Instructions, idx int) asm.RawInstructionOffset {
	return block.Raw + asm.RawInstructionOffset(insns[block.Start:idx].Size()/asm.InstructionSize)
}

// round down to nearest 8, since stack slots are 8 bytes
func roundToSlot(offset int16) int16 {
	return offset &^ 7
}

// round up to nearest 8, then divide by 8 to get number of slots
func bytesToSlots(size int16) int16 {
	return ((size + 7) &^ 7) / 8
}

type rw struct {
	Offset int16
	Block  *analyze.Block
	RawIns asm.RawInstructionOffset
}

type visitor struct {
	dbgWriter  io.Writer
	inaccurate bool

	spec            *ebpf.CollectionSpec
	insns           asm.Instructions
	inStates        map[*analyze.Block]state
	outStates       map[*analyze.Block]state
	reachableWrites map[*analyze.Block][]rw
	writes          []rw
	reads           []rw
	seenWrites      map[rw]struct{}
	seenReads       map[rw]struct{}
}

func (v *visitor) visit(entry *analyze.Block, initial state) {
	v.inStates[entry] = initial.copy()

	queue := []*analyze.Block{entry}
	inQueue := map[*analyze.Block]bool{entry: true}

	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]
		inQueue[block] = false

		out := v.transferBlock(block, v.inStates[block].copy())
		if prev, ok := v.outStates[block]; ok && statesEqual(prev, out) {
			continue
		}

		v.outStates[block] = out.copy()
		v.reachableWrites[block] = slices.Clone(out.reachableWrites)

		for _, succ := range []*analyze.Block{block.Branch, block.Fthrough} {
			if succ == nil {
				continue
			}

			nextIn, ok := v.inStates[succ]
			if !ok {
				v.inStates[succ] = out.copy()
				if !inQueue[succ] {
					queue = append(queue, succ)
					inQueue[succ] = true
				}
				continue
			}

			merged := mergeState(nextIn, out)
			if statesEqual(nextIn, merged) {
				continue
			}

			v.inStates[succ] = merged
			if !inQueue[succ] {
				queue = append(queue, succ)
				inQueue[succ] = true
			}
		}
	}
}

func (v *visitor) transferBlock(block *analyze.Block, state state) state {
	for i := block.Start; i <= block.End; i++ {
		_, _ = fmt.Fprintf(v.dbgWriter, "%d: %v\n\t", insRawOff(block, v.insns, i), v.insns[i])
		for j, s := range state.regs {
			if j != 0 {
				_, _ = fmt.Fprint(v.dbgWriter, ", ")
			}
			_, _ = fmt.Fprintf(v.dbgWriter, "R%d: ", j)
			if s.fpPtr {
				_, _ = fmt.Fprintf(v.dbgWriter, "fp %d", s.fpOff)
			} else if s.mapPtr != nil {
				_, _ = fmt.Fprintf(v.dbgWriter, "map %s", s.mapPtr.Name)
			} else if s.hasScalar {
				_, _ = fmt.Fprintf(v.dbgWriter, "scalar %d", s.scalar)
			} else {
				_, _ = fmt.Fprint(v.dbgWriter, "U")
			}
		}
		_, _ = fmt.Fprint(v.dbgWriter, "\n\t")
		printed := 0
		for _, off := range slices.Sorted(maps.Keys(state.stack)) {
			s := state.stack[off]

			var desc string
			if s.spilled.fpPtr {
				desc = fmt.Sprintf("fp %d", s.spilled.fpOff)
			} else if s.spilled.mapPtr != nil {
				desc = fmt.Sprintf("map %s", s.spilled.mapPtr.Name)
			} else if s.spilled.hasScalar {
				desc = fmt.Sprintf("scalar %d", s.spilled.scalar)
			} else {
				continue
			}

			if printed != 0 {
				_, _ = fmt.Fprint(v.dbgWriter, ", ")
			}
			_, _ = fmt.Fprintf(v.dbgWriter, "SP[%d]: %s", off, desc)
			printed++
		}
		_, _ = fmt.Fprintln(v.dbgWriter)

		ins := &v.insns[i]
		switch ins.OpCode.Class() {
		case asm.ALUClass, asm.ALU64Class:
			switch ins.OpCode.ALUOp() {
			case asm.Mov:
				// Register to register move
				if ins.OpCode.Source() == asm.RegSource {
					// Making a copy of R10 means a pointer to the frame pointer
					if ins.Src == asm.R10 {
						state.regs[ins.Dst] = regState{
							fpPtr:    true,
							fpSetOff: insRawOff(block, v.insns, i),
							fpOff:    0,
						}
						continue
					}

					// Otherwise state of one register is transferred to another
					state.regs[ins.Dst] = state.regs[ins.Src]
					continue
				}

				state.regs[ins.Dst] = regState{
					hasScalar: true,
					scalar:    int64(ins.Constant),
				}

			case asm.Add:
				// Special case: when adding a constant to a copy of rfp, track its offset
				if state.regs[ins.Dst].fpPtr && ins.OpCode.Source() == asm.ImmSource {
					state.regs[ins.Dst].fpOff += int16(ins.Constant)
					continue
				}

				fallthrough
			default:
				if state.regs[ins.Dst].hasScalar {
					var err error
					if ins.OpCode.Source() == asm.ImmSource {
						state.regs[ins.Dst].scalar, err = goAluOp(state.regs[ins.Dst].scalar, int64(ins.Constant), ins.OpCode.ALUOp(), ins.OpCode.Class() == asm.ALUClass)
						if err != nil {
							state.regs[ins.Dst].scalar = 0
							state.regs[ins.Dst].hasScalar = false
							_, _ = fmt.Fprintf(v.dbgWriter, "WARN: unsupported ALU operation at %d: %v\n", insRawOff(block, v.insns, i), err)
							continue
						}
						continue
					}

					if ins.OpCode.Source() == asm.RegSource && state.regs[ins.Src].hasScalar {
						state.regs[ins.Dst].scalar, err = goAluOp(state.regs[ins.Dst].scalar, state.regs[ins.Src].scalar, ins.OpCode.ALUOp(), ins.OpCode.Class() == asm.ALUClass)
						if err != nil {
							state.regs[ins.Dst].scalar = 0
							state.regs[ins.Dst].hasScalar = false
							_, _ = fmt.Fprintf(v.dbgWriter, "WARN: unsupported ALU operation at %d: %v\n", insRawOff(block, v.insns, i), err)
							continue
						}
						continue
					}

					// If a scalar gets mixed with a non-scalar, we lose track of it
					state.regs[ins.Dst].scalar = 0
					state.regs[ins.Dst].hasScalar = false
				}
			}
		case asm.JumpClass, asm.Jump32Class:
			if ins.OpCode.JumpOp() == asm.Call {
				// A call can count as read or write of stack.
				v.handleCall(&state, block, i)

				continue
			}
		case asm.StClass, asm.StXClass:
			if ins.Dst != asm.R10 {
				continue
			}

			off := roundToSlot(ins.Offset)
			size := int16(ins.OpCode.Size())
			v.writeStack(off, size, &state, block, i)

			// Track spilled value for later loads. Partial writes invalidate any known value.
			st := state.stack[off]
			if size < 8 {
				st.spilled = regState{}
			} else if ins.OpCode.Class() == asm.StXClass {
				st.spilled = state.regs[ins.Src]
			} else {
				st.spilled = regState{hasScalar: true, scalar: int64(ins.Constant)}
			}
			state.stack[off] = st

		case asm.LdClass, asm.LdXClass:

			if ins.IsLoadFromMap() {
				if ins.Reference() == "" {
					_, _ = fmt.Fprintln(v.dbgWriter, "WARN: missing map reference")
				}
				mapSpec, found := v.spec.Maps[ins.Reference()]
				if !found {
					_, _ = fmt.Fprintf(v.dbgWriter, "WARN: map %s not found in collection\n", ins.Reference())
					continue
				}
				state.regs[ins.Dst] = regState{
					mapPtr: mapSpec,
				}
				continue
			}

			if ins.Src != asm.R10 {
				continue
			}

			switch ins.OpCode.Mode() {
			case asm.MemMode:
				// take known value of stack and put it in the register
				state.regs[ins.Dst] = state.stack[roundToSlot(ins.Offset)].spilled
			case asm.ImmMode:
				if ins.OpCode.Size() == asm.DWord {
					state.regs[ins.Dst] = regState{
						hasScalar: true,
						scalar:    int64(ins.Constant),
					}
				}
			}

			v.readStack(state, ins.Offset, block, i)
		default:
			continue
		}
	}

	return state
}

func mergeState(a, b state) state {
	var out state
	for i := range out.regs {
		out.regs[i] = mergeRegState(a.regs[i], b.regs[i])
	}

	out.stack = make(map[int16]stackState)
	for _, off := range slices.Sorted(maps.Keys(a.stack)) {
		out.stack[off] = a.stack[off]
	}
	for _, off := range slices.Sorted(maps.Keys(b.stack)) {
		cur, found := out.stack[off]
		if !found {
			out.stack[off] = b.stack[off]
			continue
		}

		cur.spilled = mergeRegState(cur.spilled, b.stack[off].spilled)
		out.stack[off] = cur
	}

	out.reachableWrites = appendRWUnique(out.reachableWrites, a.reachableWrites...)
	out.reachableWrites = appendRWUnique(out.reachableWrites, b.reachableWrites...)

	return out
}

func mergeRegState(a, b regState) regState {
	if a == b {
		return a
	}

	// Conflicting facts collapse to unknown to guarantee convergence.
	return regState{}
}

func statesEqual(a, b state) bool {
	if a.regs != b.regs {
		return false
	}

	if len(a.stack) != len(b.stack) {
		return false
	}
	for off, as := range a.stack {
		bs, found := b.stack[off]
		if !found || as != bs {
			return false
		}
	}

	if len(a.reachableWrites) != len(b.reachableWrites) {
		return false
	}
	bWrites := make(map[rw]struct{}, len(b.reachableWrites))
	for _, write := range b.reachableWrites {
		bWrites[write] = struct{}{}
	}
	for _, write := range a.reachableWrites {
		if _, found := bWrites[write]; !found {
			return false
		}
	}

	return true
}

func appendRWUnique(dst []rw, src ...rw) []rw {
	if len(src) == 0 {
		return dst
	}

	seen := make(map[rw]struct{}, len(dst)+len(src))
	for _, item := range dst {
		seen[item] = struct{}{}
	}
	for _, item := range src {
		if _, found := seen[item]; found {
			continue
		}
		dst = append(dst, item)
		seen[item] = struct{}{}
	}

	return dst
}

var errUnsupportedALUOp = fmt.Errorf("unsupported ALU operation")
var errDivisionByZero = fmt.Errorf("division by zero")
var errModuloByZero = fmt.Errorf("modulo by zero")

func goAluOp(a, b int64, op asm.ALUOp, b32 bool) (result int64, err error) {
	switch op {
	case asm.Add:
		if b32 {
			result = int64(uint32(a) + uint32(b))
		} else {
			result = int64(uint64(a) + uint64(b))
		}
	case asm.Sub:
		if b32 {
			result = int64(uint32(a) - uint32(b))
		} else {
			result = int64(uint64(a) - uint64(b))
		}
	case asm.Mul:
		if b32 {
			result = int64(uint32(a) * uint32(b))
		} else {
			result = int64(uint64(a) * uint64(b))
		}
	case asm.Div:
		if b == 0 {
			return 0, errDivisionByZero
		}
		if b32 {
			result = int64(uint32(a) / uint32(b))
		} else {
			result = int64(uint64(a) / uint64(b))
		}
	case asm.SDiv:
		if b == 0 {
			return 0, errDivisionByZero
		}
		if b32 {
			result = int64(int32(a) / int32(b))
		} else {
			result = a / b
		}
	case asm.Or:
		if b32 {
			result = int64(uint32(a) | uint32(b))
		} else {
			result = a | b
		}
	case asm.And:
		if b32 {
			result = int64(uint32(a) & uint32(b))
		} else {
			result = a & b
		}
	case asm.LSh:
		if b32 {
			result = int64(uint32(a) << (uint(b) & 31))
		} else {
			result = a << (uint(b) & 63)
		}
	case asm.RSh:
		if b32 {
			result = int64(uint32(a) >> (uint(b) & 31))
		} else {
			result = a >> (uint(b) & 63)
		}
	case asm.Neg:
		if b32 {
			result = int64(-int32(a))
		} else {
			result = -a
		}
	case asm.Mod:
		if b == 0 {
			return 0, errModuloByZero
		}
		if b32 {
			result = int64(uint32(a) % uint32(b))
		} else {
			result = int64(uint64(a) % uint64(b))
		}
	case asm.SMod:
		if b == 0 {
			return 0, errModuloByZero
		}
		if b32 {
			result = int64(int32(a) % int32(b))
		} else {
			result = a % b
		}
	case asm.Xor:
		if b32 {
			result = int64(uint32(a) ^ uint32(b))
		} else {
			result = a ^ b
		}
	case asm.ArSh:
		if b32 {
			result = int64(int32(a) >> (uint(b) & 31))
		} else {
			result = a >> (uint(b) & 63)
		}
	default:
		return 0, errUnsupportedALUOp
	}

	return result, nil
}

func (v *visitor) readStack(s state, offset int16, curBlock *analyze.Block, readInsIdx int) {
	_, _ = fmt.Fprintf(v.dbgWriter, "Read stack, off: %d\n", offset)
	_, found := s.stack[roundToSlot(offset)]
	if !found {
		_, _ = fmt.Fprintf(v.dbgWriter, "WARN: read of uninitialized stack slot %d at %d\n", roundToSlot(offset), insRawOff(curBlock, v.insns, readInsIdx))
		v.inaccurate = true
		return
	}

	read := rw{
		Offset: roundToSlot(offset),
		Block:  curBlock,
		RawIns: insRawOff(curBlock, v.insns, readInsIdx),
	}
	if _, found := v.seenReads[read]; found {
		return
	}
	v.seenReads[read] = struct{}{}
	v.reads = append(v.reads, read)
}

func (v *visitor) writeStack(offset int16, size int16, s *state, curBlock *analyze.Block, insIdx int) {
	// Where there is pre-existing state in this slot and we are only writing to part of it
	// We don't want to create a new lifetime, we want to extend the existing one.
	if _, found := s.stack[offset]; found && size < 8 {
		_, _ = fmt.Fprintf(v.dbgWriter, "Mod stack, off: %d\n", offset)
		return
	}

	_, _ = fmt.Fprintf(v.dbgWriter, "Write stack, off: %d\n", offset)

	s.stack[offset] = stackState{}
	callW := rw{
		Offset: offset,
		Block:  curBlock,
		RawIns: insRawOff(curBlock, v.insns, insIdx),
	}
	s.reachableWrites = appendRWUnique(s.reachableWrites, callW)
	if _, found := v.seenWrites[callW]; found {
		return
	}
	v.seenWrites[callW] = struct{}{}
	v.writes = append(v.writes, callW)
}

func (v *visitor) handleCall(s *state, curBlock *analyze.Block, insIdx int) {
	ins := v.insns[insIdx]

	if ins.IsKfuncCall() {
		// TODO handle kfuncs
		_, _ = fmt.Fprintf(v.dbgWriter, "WARN: kfunc call at %d, not handled\n", insRawOff(curBlock, v.insns, insIdx))
		v.inaccurate = true
		return
	}

	if !ins.IsBuiltinCall() {
		// TODO handle static bpf to bpf calls (global funcs are separate programs)
		_, _ = fmt.Fprintf(v.dbgWriter, "WARN: bpf to bpf call at %d, not handled\n", insRawOff(curBlock, v.insns, insIdx))
		v.inaccurate = true
		return
	}

	clobberR0 := true
	defer func() {
		i := asm.R1
		if clobberR0 {
			i = asm.R0
		}
		for j := i; j <= asm.R5; j++ {
			s.regs[j] = regState{}
		}
	}()

	// Maps are special, they do not have a size parameter, size is inferred from the map definition.
	switch asm.BuiltinFunc(ins.Constant) {
	case asm.FnMapLookupElem, asm.FnMapDeleteElem:
		if s.regs[asm.R1].mapPtr == nil {
			_, _ = fmt.Fprintf(v.dbgWriter, "WARN: map lookup with non-map pointer at %d\n", insRawOff(curBlock, v.insns, insIdx))
			return
		}

		mapSpec := s.regs[asm.R1].mapPtr
		keyPtr := s.regs[asm.R2]
		if !keyPtr.fpPtr {
			// Key is not located on the stack, this is allowed when the key is another map value.
			return
		}

		slots := bytesToSlots(int16(mapSpec.KeySize))
		for i := range slots {
			v.readStack(*s, keyPtr.fpOff+i*8, curBlock, insIdx)
		}

		if mapSpec.InnerMap != nil {
			clobberR0 = false
			s.regs[asm.R0] = regState{
				mapPtr: mapSpec.InnerMap,
			}
		}

		return

	case asm.FnMapUpdateElem:
		if s.regs[asm.R1].mapPtr == nil {
			_, _ = fmt.Fprintf(v.dbgWriter, "WARN: map lookup with non-map pointer at %d\n", insRawOff(curBlock, v.insns, insIdx))
			return
		}

		mapSpec := s.regs[asm.R1].mapPtr
		keyPtr := s.regs[asm.R2]
		// Key is not located on the stack, this is allowed when the key is another map value.
		if keyPtr.fpPtr {
			slots := bytesToSlots(int16(mapSpec.KeySize))
			for i := range slots {
				v.readStack(*s, keyPtr.fpOff+i*8, curBlock, insIdx)
			}
		}

		valuePtr := s.regs[asm.R3]
		// Key is not located on the stack, this is allowed when the key is another map value.
		if valuePtr.fpPtr {
			slots := bytesToSlots(int16(mapSpec.ValueSize))
			for i := range slots {
				v.readStack(*s, valuePtr.fpOff+i*8, curBlock, insIdx)
			}
		}

		return
	case asm.FnSockMapUpdate, asm.FnSockHashUpdate, asm.FnMsgRedirectHash, asm.FnSkRedirectHash,
		asm.FnSkSelectReuseport,
		asm.FnMapPushElem, asm.FnMapPopElem, asm.FnMapPeekElem,
		asm.FnSkStorageGet, asm.FnInodeStorageGet, asm.FnTaskStorageGet, asm.FnCgrpStorageGet,
		asm.FnMapLookupPercpuElem:
		// TODO implement map related helpers
		_, _ = fmt.Fprintf(v.dbgWriter, "WARN: map related helper %s at %d, not handled\n", asm.BuiltinFunc(ins.Constant), insRawOff(curBlock, v.insns, insIdx))
		v.inaccurate = true
		return
	case asm.FnDynptrFromMem, asm.FnRingbufReserveDynptr, asm.FnRingbufSubmitDynptr,
		asm.FnRingbufDiscardDynptr, asm.FnDynptrRead, asm.FnDynptrWrite, asm.FnDynptrData:
		// TODO implement dynamic pointer tracking, so reads/writes to dynamic pointer propagate to the underlying memory
		_, _ = fmt.Fprintf(v.dbgWriter, "WARN: dynamic pointer helper %s at %d, not handled\n", asm.BuiltinFunc(ins.Constant), insRawOff(curBlock, v.insns, insIdx))
		v.inaccurate = true
		return
	}

	argPairs, found := callArgMap[asm.BuiltinFunc(ins.Constant)]
	if !found {
		_, _ = fmt.Fprintf(v.dbgWriter, "WARN: unhandled call to unknown helper function %s at %d\n", asm.BuiltinFunc(ins.Constant), insRawOff(curBlock, v.insns, insIdx))
		v.inaccurate = true
		return
	}

	for _, argPair := range argPairs {
		ptrState := s.regs[argPair.ptr]
		if !ptrState.fpPtr {
			_, _ = fmt.Fprintf(v.dbgWriter, "WARN: pointer argument is not a frame pointer at %d\n", insRawOff(curBlock, v.insns, insIdx))
			// Note: do not mark inaccurate here, since the pointer could be a map value, which is allowed to be non-frame pointer.
			continue
		}

		size := int64(0)
		if argPair.sizeConst != 0 {
			size = argPair.sizeConst
		} else {
			sizeState := s.regs[argPair.size]
			if !sizeState.hasScalar {
				_, _ = fmt.Fprintf(v.dbgWriter, "WARN: size argument is not a scalar at %d\n", insRawOff(curBlock, v.insns, insIdx))
				v.inaccurate = true
				continue
			}

			if sizeState.scalar > 512 {
				_, _ = fmt.Fprintf(v.dbgWriter, "WARN: size argument is too large at %d\n", insRawOff(curBlock, v.insns, insIdx))
				v.inaccurate = true
				continue
			}
			size = sizeState.scalar
		}

		if argPair.rw&Read != 0 {
			slots := bytesToSlots(int16(size))
			for i := range slots {
				v.readStack(*s, roundToSlot(ptrState.fpOff)+int16(i*8), curBlock, insIdx)
			}
		}
		if argPair.rw&Write != 0 {
			slots := bytesToSlots(int16(size))
			for i := range slots {
				off := roundToSlot(ptrState.fpOff) + int16(i*8)
				v.writeStack(off, int16(size), s, curBlock, insIdx)
			}
		}
	}
}

type callArgRW int

const (
	Read callArgRW = 1 << iota
	Write
	ReadWrite = Read | Write
)

type callArgPair struct {
	ptr       asm.Register
	size      asm.Register
	rw        callArgRW
	sizeConst int64
}

func PSPair(ptr, size asm.Register, rw callArgRW) callArgPair {
	return callArgPair{
		ptr:  ptr,
		size: size,
		rw:   rw,
	}
}

func PConst(ptr asm.Register, size int64, rw callArgRW) callArgPair {
	return callArgPair{
		ptr:       ptr,
		sizeConst: size,
		rw:        rw,
	}
}

var callArgMap = map[asm.BuiltinFunc][]callArgPair{
	asm.FnMapLookupElem:              {}, // Covered by special case
	asm.FnMapDeleteElem:              {}, // Covered by special case
	asm.FnMapUpdateElem:              {}, // Covered by special case
	asm.FnProbeRead:                  {PSPair(asm.R1, asm.R2, Write)},
	asm.FnKtimeGetNs:                 {},
	asm.FnTracePrintk:                {PSPair(asm.R1, asm.R2, Read)},
	asm.FnGetPrandomU32:              {},
	asm.FnGetSmpProcessorId:          {},
	asm.FnSkbStoreBytes:              {PSPair(asm.R3, asm.R4, Read)},
	asm.FnL3CsumReplace:              {},
	asm.FnL4CsumReplace:              {},
	asm.FnTailCall:                   {},
	asm.FnCloneRedirect:              {},
	asm.FnGetCurrentPidTgid:          {},
	asm.FnGetCurrentUidGid:           {},
	asm.FnGetCurrentComm:             {PSPair(asm.R1, asm.R2, Write)},
	asm.FnGetCgroupClassid:           {},
	asm.FnSkbVlanPush:                {},
	asm.FnSkbVlanPop:                 {},
	asm.FnSkbGetTunnelKey:            {PSPair(asm.R2, asm.R3, Write)},
	asm.FnSkbSetTunnelKey:            {PSPair(asm.R2, asm.R3, Read)},
	asm.FnPerfEventRead:              {},
	asm.FnRedirect:                   {},
	asm.FnGetRouteRealm:              {},
	asm.FnPerfEventOutput:            {PSPair(asm.R4, asm.R5, Read)},
	asm.FnSkbLoadBytes:               {PSPair(asm.R3, asm.R4, Write)},
	asm.FnGetStackid:                 {},
	asm.FnCsumDiff:                   {},
	asm.FnSkbGetTunnelOpt:            {PSPair(asm.R2, asm.R3, Write)},
	asm.FnSkbSetTunnelOpt:            {PSPair(asm.R2, asm.R3, Read)},
	asm.FnSkbChangeProto:             {},
	asm.FnSkbChangeType:              {},
	asm.FnSkbUnderCgroup:             {},
	asm.FnGetHashRecalc:              {},
	asm.FnGetCurrentTask:             {},
	asm.FnProbeWriteUser:             {PSPair(asm.R2, asm.R3, Read)},
	asm.FnCurrentTaskUnderCgroup:     {},
	asm.FnSkbChangeTail:              {},
	asm.FnSkbPullData:                {},
	asm.FnCsumUpdate:                 {},
	asm.FnSetHashInvalid:             {},
	asm.FnGetNumaNodeId:              {},
	asm.FnSkbChangeHead:              {},
	asm.FnXdpAdjustHead:              {},
	asm.FnProbeReadStr:               {PSPair(asm.R1, asm.R2, Write)},
	asm.FnGetSocketCookie:            {},
	asm.FnGetSocketUid:               {},
	asm.FnSetHash:                    {},
	asm.FnSetsockopt:                 {PSPair(asm.R4, asm.R5, Read)},
	asm.FnSkbAdjustRoom:              {},
	asm.FnRedirectMap:                {},
	asm.FnSkRedirectMap:              {},
	asm.FnSockMapUpdate:              {}, // Covered by special case
	asm.FnXdpAdjustMeta:              {},
	asm.FnPerfEventReadValue:         {PSPair(asm.R3, asm.R4, Write)},
	asm.FnPerfProgReadValue:          {PSPair(asm.R2, asm.R3, Write)},
	asm.FnGetsockopt:                 {PSPair(asm.R4, asm.R5, Write)},
	asm.FnOverrideReturn:             {},
	asm.FnSockOpsCbFlagsSet:          {},
	asm.FnMsgRedirectMap:             {},
	asm.FnMsgApplyBytes:              {},
	asm.FnMsgCorkBytes:               {},
	asm.FnMsgPullData:                {},
	asm.FnBind:                       {PSPair(asm.R2, asm.R3, Read)},
	asm.FnXdpAdjustTail:              {},
	asm.FnSkbGetXfrmState:            {PSPair(asm.R3, asm.R4, Write)},
	asm.FnGetStack:                   {PSPair(asm.R2, asm.R3, Write)},
	asm.FnSkbLoadBytesRelative:       {PSPair(asm.R3, asm.R4, Write)},
	asm.FnFibLookup:                  {PSPair(asm.R2, asm.R3, ReadWrite)},
	asm.FnSockHashUpdate:             {}, // Handled by special case
	asm.FnMsgRedirectHash:            {},
	asm.FnSkRedirectHash:             {},
	asm.FnLwtPushEncap:               {PSPair(asm.R3, asm.R4, Read)},
	asm.FnLwtSeg6StoreBytes:          {PSPair(asm.R3, asm.R4, Read)},
	asm.FnLwtSeg6AdjustSrh:           {},
	asm.FnLwtSeg6Action:              {PSPair(asm.R3, asm.R4, Write)},
	asm.FnRcRepeat:                   {},
	asm.FnRcKeydown:                  {},
	asm.FnSkbCgroupId:                {},
	asm.FnGetCurrentCgroupId:         {},
	asm.FnGetLocalStorage:            {},
	asm.FnSkSelectReuseport:          {}, // handled by special case
	asm.FnSkbAncestorCgroupId:        {},
	asm.FnSkLookupTcp:                {PSPair(asm.R2, asm.R3, Read)},
	asm.FnSkLookupUdp:                {PSPair(asm.R2, asm.R3, Read)},
	asm.FnSkRelease:                  {},
	asm.FnMapPushElem:                {}, // handled by special case
	asm.FnMapPopElem:                 {}, // handled by special case
	asm.FnMapPeekElem:                {}, // handled by special case
	asm.FnMsgPushData:                {},
	asm.FnMsgPopData:                 {},
	asm.FnRcPointerRel:               {},
	asm.FnSpinLock:                   {},
	asm.FnSpinUnlock:                 {},
	asm.FnSkFullsock:                 {},
	asm.FnTcpSock:                    {},
	asm.FnSkbEcnSetCe:                {},
	asm.FnGetListenerSock:            {},
	asm.FnSkcLookupTcp:               {PSPair(asm.R2, asm.R3, Read)},
	asm.FnTcpCheckSyncookie:          {PSPair(asm.R2, asm.R3, Read), PSPair(asm.R4, asm.R5, Read)},
	asm.FnSysctlGetName:              {PSPair(asm.R2, asm.R3, Write)},
	asm.FnSysctlGetCurrentValue:      {PSPair(asm.R2, asm.R3, Write)},
	asm.FnSysctlGetNewValue:          {PSPair(asm.R2, asm.R3, Write)},
	asm.FnSysctlSetNewValue:          {PSPair(asm.R2, asm.R3, Read)},
	asm.FnStrtol:                     {PSPair(asm.R1, asm.R2, Read), PConst(asm.R4, 4, Write)},
	asm.FnStrtoul:                    {PSPair(asm.R1, asm.R2, Read), PConst(asm.R4, 4, Write)},
	asm.FnSkStorageGet:               {}, // handle by special case
	asm.FnSkStorageDelete:            {},
	asm.FnSendSignal:                 {},
	asm.FnTcpGenSyncookie:            {PSPair(asm.R2, asm.R3, Read), PSPair(asm.R4, asm.R5, Read)},
	asm.FnSkbOutput:                  {PSPair(asm.R4, asm.R5, Read)},
	asm.FnProbeReadUser:              {PSPair(asm.R1, asm.R2, Write)},
	asm.FnProbeReadKernel:            {PSPair(asm.R1, asm.R2, Write)},
	asm.FnProbeReadUserStr:           {PSPair(asm.R1, asm.R2, Write)},
	asm.FnProbeReadKernelStr:         {PSPair(asm.R1, asm.R2, Write)},
	asm.FnTcpSendAck:                 {},
	asm.FnSendSignalThread:           {},
	asm.FnJiffies64:                  {},
	asm.FnReadBranchRecords:          {PSPair(asm.R2, asm.R3, Write)},
	asm.FnGetNsCurrentPidTgid:        {PSPair(asm.R3, asm.R4, Write)},
	asm.FnXdpOutput:                  {PSPair(asm.R4, asm.R5, Read)},
	asm.FnGetNetnsCookie:             {},
	asm.FnGetCurrentAncestorCgroupId: {},
	asm.FnSkAssign:                   {},
	asm.FnKtimeGetBootNs:             {},
	asm.FnSeqPrintf:                  {PSPair(asm.R2, asm.R3, Read), PSPair(asm.R4, asm.R5, Read)},
	asm.FnSeqWrite:                   {PSPair(asm.R2, asm.R3, Read)},
	asm.FnSkCgroupId:                 {},
	asm.FnSkAncestorCgroupId:         {},
	asm.FnRingbufOutput:              {PSPair(asm.R2, asm.R3, Read)},
	asm.FnRingbufReserve:             {},
	asm.FnRingbufSubmit:              {},
	asm.FnRingbufDiscard:             {},
	asm.FnRingbufQuery:               {},
	asm.FnCsumLevel:                  {},
	asm.FnSkcToTcp6Sock:              {},
	asm.FnSkcToTcpSock:               {},
	asm.FnSkcToTcpTimewaitSock:       {},
	asm.FnSkcToTcpRequestSock:        {},
	asm.FnSkcToUdp6Sock:              {},
	asm.FnGetTaskStack:               {PSPair(asm.R2, asm.R3, Write)},
	asm.FnLoadHdrOpt:                 {PSPair(asm.R2, asm.R3, ReadWrite)},
	asm.FnStoreHdrOpt:                {PSPair(asm.R2, asm.R3, Read)},
	asm.FnReserveHdrOpt:              {},
	asm.FnInodeStorageGet:            {}, // handled by special case
	asm.FnInodeStorageDelete:         {},
	asm.FnDPath:                      {PSPair(asm.R2, asm.R3, Write)},
	asm.FnCopyFromUser:               {PSPair(asm.R1, asm.R2, Write)},
	asm.FnSnprintfBtf:                {PSPair(asm.R1, asm.R2, Write), PSPair(asm.R3, asm.R4, Read)},
	asm.FnSeqPrintfBtf:               {PSPair(asm.R2, asm.R3, Read)},
	asm.FnSkbCgroupClassid:           {},
	asm.FnRedirectNeigh:              {PSPair(asm.R2, asm.R3, ReadWrite)},
	asm.FnPerCpuPtr:                  {},
	asm.FnThisCpuPtr:                 {},
	asm.FnRedirectPeer:               {},
	asm.FnTaskStorageGet:             {}, // handled by special case
	asm.FnTaskStorageDelete:          {},
	asm.FnGetCurrentTaskBtf:          {},
	asm.FnBprmOptsSet:                {},
	asm.FnKtimeGetCoarseNs:           {},
	asm.FnImaInodeHash:               {PSPair(asm.R2, asm.R3, Write)},
	asm.FnSockFromFile:               {},
	asm.FnCheckMtu:                   {},
	asm.FnForEachMapElem:             {},
	asm.FnSnprintf:                   {PSPair(asm.R1, asm.R2, Write), PSPair(asm.R4, asm.R5, Read)},
	asm.FnSysBpf:                     {PSPair(asm.R2, asm.R3, Read)},
	asm.FnBtfFindByNameKind:          {PSPair(asm.R1, asm.R2, Read)},
	asm.FnSysClose:                   {},
	asm.FnTimerInit:                  {},
	asm.FnTimerSetCallback:           {},
	asm.FnTimerStart:                 {},
	asm.FnTimerCancel:                {},
	asm.FnGetFuncIp:                  {},
	asm.FnGetAttachCookie:            {},
	asm.FnTaskPtRegs:                 {},
	asm.FnGetBranchSnapshot:          {PSPair(asm.R1, asm.R2, Write)},
	asm.FnTraceVprintk:               {PSPair(asm.R1, asm.R2, Read), PSPair(asm.R3, asm.R4, Read)},
	asm.FnSkcToUnixSock:              {},
	asm.FnKallsymsLookupName:         {PSPair(asm.R1, asm.R2, Read), PConst(asm.R4, 8, Write)},
	asm.FnFindVma:                    {},
	asm.FnLoop:                       {},
	asm.FnStrncmp:                    {PSPair(asm.R1, asm.R2, Read), PSPair(asm.R3, asm.R2, Read)},
	asm.FnGetFuncArg:                 {PConst(asm.R3, 8, Write)},
	asm.FnGetFuncRet:                 {PConst(asm.R2, 8, Write)},
	asm.FnGetFuncArgCnt:              {},
	asm.FnGetRetval:                  {},
	asm.FnSetRetval:                  {},
	asm.FnXdpGetBuffLen:              {},
	asm.FnXdpLoadBytes:               {PSPair(asm.R3, asm.R4, Write)},
	asm.FnXdpStoreBytes:              {PSPair(asm.R3, asm.R4, Read)},
	asm.FnCopyFromUserTask:           {PSPair(asm.R1, asm.R2, Write)},
	asm.FnSkbSetTstamp:               {},
	asm.FnImaFileHash:                {PSPair(asm.R2, asm.R3, Write)},
	asm.FnKptrXchg:                   {},
	asm.FnMapLookupPercpuElem:        {}, // handled by special case
	asm.FnSkcToMptcpSock:             {},
	asm.FnDynptrFromMem:              {}, // handled by special case
	asm.FnRingbufReserveDynptr:       {}, // handled by special case
	asm.FnRingbufSubmitDynptr:        {}, // handled by special case
	asm.FnRingbufDiscardDynptr:       {}, // handled by special case
	asm.FnDynptrRead:                 {}, // handled by special case
	asm.FnDynptrWrite:                {}, // handled by special case
	asm.FnDynptrData:                 {}, // handled by special case
	asm.FnTcpRawGenSyncookieIpv4:     {PConst(asm.R1, 20, Read), PSPair(asm.R2, asm.R3, Read)},
	asm.FnTcpRawGenSyncookieIpv6:     {PConst(asm.R1, 40, Read), PSPair(asm.R2, asm.R3, Read)},
	asm.FnTcpRawCheckSyncookieIpv4:   {PConst(asm.R1, 20, Read), PConst(asm.R2, 20, Read)},
	asm.FnTcpRawCheckSyncookieIpv6:   {PConst(asm.R1, 40, Read), PConst(asm.R2, 20, Read)},
	asm.FnKtimeGetTaiNs:              {},
	asm.FnUserRingbufDrain:           {},
	asm.FnCgrpStorageGet:             {}, // handled by special case
	asm.FnCgrpStorageDelete:          {},
}

func graphLifetimes(lifetimes []StackLifetime, blocks analyze.Blocks, insns asm.Instructions, writes []rw, reads []rw, drawBBB bool) string {
	lifetimeByOffset := make(map[int16][]StackLifetime)
	for _, lt := range lifetimes {
		lifetimeByOffset[lt.offset] = append(lifetimeByOffset[lt.offset], lt)
	}

	// Sort offsets ascending: most-negative (farthest from frame pointer) at top.
	offsets := slices.Collect(maps.Keys(lifetimeByOffset))
	slices.SortFunc(offsets, func(a, b int16) int { return int(a) - int(b) })

	const (
		cellW      = 8  // pixels per instruction
		rowH       = 24 // pixels per stack slot row
		marginLeft = 64 // space for offset labels
		marginTop  = 28 // space for instruction index labels
	)

	palette := []string{
		"#4e79a7", "#f28e2b", "#e15759", "#76b7b2",
		"#59a14f", "#edc948", "#b07aa1", "#ff9da7",
		"#9c755f", "#bab0ac",
	}

	nInsns := int(insRawOff(blocks[len(blocks)-1], insns, len(insns)-1) + 1)
	nSlots := len(offsets)
	totalW := marginLeft + nInsns*cellW + 1
	totalH := marginTop + nSlots*rowH + 1

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" style="background:white">`,
		totalW, totalH)

	// Row backgrounds and offset labels on the left.
	for i, off := range offsets {
		y := marginTop + i*rowH
		bg := "#ffffff"
		if i%2 != 0 {
			bg = "#f5f5f5"
		}
		fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`,
			marginLeft, y, nInsns*cellW, rowH, bg)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="11" text-anchor="end" dominant-baseline="middle" font-family="monospace" fill="#333">%d</text>`,
			marginLeft-4, y+rowH/2, off)
	}

	// Vertical grid lines and instruction index tick labels.
	step := 1
	switch {
	case nInsns > 500:
		step = 50
	case nInsns > 200:
		step = 20
	case nInsns > 100:
		step = 10
	case nInsns > 50:
		step = 5
	}
	for i := 0; i < nInsns; i += step {
		x := marginLeft + i*cellW
		fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#ddd" stroke-width="0.5"/>`,
			x, marginTop, x, marginTop+nSlots*rowH)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="10" text-anchor="middle" font-family="monospace" fill="#555">%d</text>`,
			x, marginTop-6, i)
	}

	if drawBBB {
		// Basic block boundaries at block entry points.
		boundarySet := make(map[asm.RawInstructionOffset]struct{}, len(blocks))
		for _, block := range blocks {
			boundarySet[block.Raw] = struct{}{}
		}

		boundaries := slices.Collect(maps.Keys(boundarySet))
		slices.Sort(boundaries)
		for _, boundary := range boundaries {
			x := marginLeft + int(boundary)*cellW
			fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#666" stroke-width="0.75"/>`,
				x, marginTop, x, marginTop+nSlots*rowH)
		}
	}

	// Lifetime boxes: one color per lifetime, same color across all its intervals.
	for i, off := range offsets {
		y := marginTop + i*rowH
		for li, lt := range lifetimeByOffset[off] {
			color := palette[li%len(palette)]
			for _, interval := range lt.lifetime.Intervals {
				x := marginLeft + interval.Start*cellW
				w := (interval.End - interval.Start + 1) * cellW
				if w < 1 {
					w = 1
				}
				fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" fill="%s" stroke="rgba(0,0,0,0.25)" stroke-width="1" rx="2"/>`,
					x, y+3, w, rowH-6, color)
			}
		}
	}

	// Build offset-to-row index for marker placement.
	offsetToRow := make(map[int16]int, len(offsets))
	for i, off := range offsets {
		offsetToRow[off] = i
	}

	// Write markers: filled black circles.
	for _, w := range writes {
		rowIdx, ok := offsetToRow[w.Offset]
		if !ok {
			continue
		}
		cx := marginLeft + int(w.RawIns)*cellW + cellW/2
		cy := marginTop + rowIdx*rowH + rowH/2
		fmt.Fprintf(&sb, `<circle class="lifetime-dot lifetime-dot-write" data-raw="%d" cx="%d" cy="%d" r="4" fill="black"/>`, w.RawIns, cx, cy)
	}

	// Read markers: white circles with black stroke.
	for _, r := range reads {
		rowIdx, ok := offsetToRow[r.Offset]
		if !ok {
			continue
		}
		cx := marginLeft + int(r.RawIns)*cellW + cellW/2
		cy := marginTop + rowIdx*rowH + rowH/2
		fmt.Fprintf(&sb, `<circle class="lifetime-dot lifetime-dot-read" data-raw="%d" cx="%d" cy="%d" r="4" fill="white" stroke="black" stroke-width="1.5"/>`, r.RawIns, cx, cy)
	}

	// Border around the chart area.
	fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="#aaa" stroke-width="1"/>`,
		marginLeft, marginTop, nInsns*cellW, nSlots*rowH)

	fmt.Fprintf(&sb, `</svg>`)
	return sb.String()
}
