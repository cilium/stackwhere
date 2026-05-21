// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf/asm"
)

// leaderKey is used to store the leader metadata in an instruction's metadata.
type leaderKey struct{}

// A leader is an instruction at the beginning of a basic block.
type leader struct {
	// predecessors are instructions in other blocks that are always executed
	// before this instruction.
	predecessors []*asm.Instruction

	// block is the block that this instruction is the start of.
	block *Block
}

// setLeaderMeta sets the leader metadata for an instruction. This metadata
// is used to mark the start of a basic block and to store information about
// the block and its predecessors.
func setLeaderMeta(ins *asm.Instruction, meta *leader) {
	ins.Metadata.Set(leaderKey{}, meta)
}

// getLeaderMeta retrieves the leader metadata for an instruction.
func getLeaderMeta(ins *asm.Instruction) *leader {
	val := ins.Metadata.Get(leaderKey{})
	meta, ok := val.(*leader)
	if !ok {
		return nil
	}
	return meta
}

// setLeader idempotently sets the leader metadata for an instruction, returning
// the existing leader metadata if it already exists.
func setLeader(ins *asm.Instruction) *leader {
	l := getLeaderMeta(ins)
	if l == nil {
		l = &leader{}
		setLeaderMeta(ins, l)
	}
	return l
}

// addPredecessors adds one or more predecessor instructions to the list of
// predecessors for the given instruction. If a predecessor is already in the
// list, it is not added again.
//
// This is used to track the control flow graph of the program, where each
// instruction can have multiple predecessors (i.e. it can be reached from
// multiple branches). Initializes the instruction's leader metadata if it does
// not exist yet.
func addPredecessors(ins *asm.Instruction, preds ...*asm.Instruction) {
	l := setLeader(ins)
	for _, pred := range preds {
		if pred == nil {
			continue
		}
		if !slices.Contains(l.predecessors, pred) {
			l.predecessors = append(l.predecessors, pred)
		}
	}
}

// edgeKey is used to store the edge metadata in an instruction's metadata.
type edgeKey struct{}

// edge is a metadata structure that is associated with an instruction marking
// the end of a basic block. It can have a branch target (the target of a jump
// instruction) and a fallthrough target (the next instruction in the
// instruction stream that is executed if the branch is not taken).
type edge struct {
	branch   *asm.Instruction
	fthrough *asm.Instruction

	block *Block
}

// setEdgeMeta sets the edge metadata for an instruction.
func setEdgeMeta(ins *asm.Instruction, meta *edge) {
	ins.Metadata.Set(edgeKey{}, meta)
}

// getEdgeMeta retrieves the edge metadata for an instruction.
func getEdgeMeta(ins *asm.Instruction) *edge {
	val := ins.Metadata.Get(edgeKey{})
	meta, ok := val.(*edge)
	if !ok {
		return nil
	}
	return meta
}

// setEdge idempotently sets the edge metadata for an instruction, returning the
// existing edge metadata if it already exists.
func setEdge(ins *asm.Instruction) *edge {
	e := getEdgeMeta(ins)
	if e == nil {
		e = &edge{}
		setEdgeMeta(ins, e)
	}
	return e
}

// setEdgeBranchTarget sets the branch target for an edge instruction. This is
// used to mark the target of a jump instruction that branches to another basic
// block.
func setEdgeBranchTarget(ins *asm.Instruction, target *asm.Instruction) {
	e := setEdge(ins)
	e.branch = target
}

// setEdgeFallthrough sets the fallthrough target for an edge instruction. This
// is used to mark the next instruction in the instruction stream that is
// executed if the branch is not taken, typically the instruction immediately
// following the branch instruction.
func setEdgeFallthrough(ins *asm.Instruction, target *asm.Instruction) {
	e := setEdge(ins)
	e.fthrough = target
}

// setEdgeExit marks an instruction as an edge with no branch target, and
// optionally marks the next instruction as a leader. This is used for exit
// instructions that terminate a basic block without branching to another block.
func setEdgeExit(ins, next *asm.Instruction) {
	setEdge(ins)
	if next != nil {
		setLeader(next)
	}
}

// setBranchTarget creates a two-way association between both the branch
// instruction and its target instruction, as well as the target instruction and
// its natural predecessor. prev may be nil if the branch target is the first
// instruction in the program.
//
// This process creates two edges and a leader, updating existing metadata if
// the instructions were already marked as leaders or edges.
func setBranchTarget(branch, target, prev *asm.Instruction) {
	// Associate the branch instruction with its target. The target becomes a
	// leader, the branch instruction becomes an edge.
	setEdgeBranchTarget(branch, target)

	// Create a reverse link from the branch target to both the branch (jump)
	// instructions and the target's predecessor.
	if canFallthrough(prev) {
		// Creating a leader implicitly means making the instruction before it an
		// edge with a fallthrough target. Associate the target with its predecessor.
		setEdgeFallthrough(prev, target)
		addPredecessors(target, branch, prev)
	} else {
		// If the instruction preceding the branch target cannot fall through (Ja,
		// Exit), don't register it as a predecessor.
		if prev != nil {
			setEdge(prev)
		}
		addPredecessors(target, branch)
	}
}

// setBranchFallthrough sets the fallthrough target for a branch instruction.
func setBranchFallthrough(branch, fthrough *asm.Instruction) {
	if fthrough == nil || !canFallthrough(branch) {
		return
	}

	setEdgeFallthrough(branch, fthrough)
	addPredecessors(fthrough, branch)
}

// A Block is a contiguous sequence of instructions that are executed together.
// Boundaries are defined by branching instructions.
//
// Blocks are attached to instructions via metadata and should not be modified
// after being created.
//
// It should never contain direct references to the original asm.Instructions
// since copying the ProgramSpec won't update pointers to the new copied insns.
// This is a problem when modifying instructions through
// [Blocks.LiveInstructions] after reachability analysis, since it would modify
// the original ProgramSpec's instructions.
type Block struct {
	ID         uint64
	Raw        asm.RawInstructionOffset
	Start, End int

	// If this block is the start of a function, sym is set to the function name.
	sym string

	Predecessors []*Block
	Branch       *Block
	Fthrough     *Block

	// calls are blocks that are called from this block.
	calls []*Block
}

func (b *Block) leader(insns asm.Instructions) *leader {
	if len(insns) == 0 {
		return nil
	}
	return getLeaderMeta(&insns[b.Start])
}

func (b *Block) last(insns asm.Instructions) *asm.Instruction {
	if len(insns) == 0 {
		return nil
	}

	if b.End >= len(insns) {
		return nil
	}

	return &insns[b.End]
}

func (b *Block) edge(insns asm.Instructions) *edge {
	last := b.last(insns)
	if last == nil {
		return nil
	}

	return getEdgeMeta(last)
}

func (b *Block) String() string {
	return b.Dump(nil)
}

func (b *Block) Dump(insns asm.Instructions) string {
	var sb strings.Builder

	if b.sym != "" {
		_, _ = fmt.Fprintf(&sb, "Function: %s\n", b.sym)
	}

	sb.WriteString("Predecessors: [")
	for i, from := range b.Predecessors {
		if i > 0 {
			_, _ = sb.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&sb, "%d", from.ID)
	}
	_, _ = sb.WriteString("]\n")
	_, _ = fmt.Fprintf(&sb, "Start: %d (raw %d), end: %d\n", b.Start, b.Raw, b.End)
	_, _ = sb.WriteString("\n")

	if len(insns) != 0 {
		sb.WriteString("Instructions:\n")
		off := asm.RawInstructionOffset(b.Raw)
		for i := b.Start; i <= b.End; i++ {
			ins := &insns[i]
			if ins.Symbol() != "" {
				fmt.Fprintf(&sb, "\t%s:\n", ins.Symbol())
			}
			if src := ins.Source(); src != nil {
				line := strings.TrimSpace(src.String())
				if line != "" {
					fmt.Fprintf(&sb, "\t%*s; %s\n", 4, " ", line)
				}
			}
			fmt.Fprintf(&sb, "\t%*d: %v\n", 4, off, ins)
			off += asm.RawInstructionOffset(ins.Size() / asm.InstructionSize)
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("Instructions: not provided, call Dump() with insns\n")
	}

	if len(b.calls) > 0 {
		sb.WriteString("Calls: [")
		for i, callee := range b.calls {
			if i > 0 {
				_, _ = sb.WriteString(", ")
			}
			_, _ = fmt.Fprintf(&sb, "%d", callee.ID)
		}
		_, _ = sb.WriteString("]\n")
	}

	if b.Branch != nil {
		_, _ = sb.WriteString("Branch: ")
		_, _ = fmt.Fprintf(&sb, "%d", b.Branch.ID)
		_, _ = sb.WriteString("\n")
	}

	if b.Fthrough != nil {
		_, _ = sb.WriteString("Fallthrough: ")
		_, _ = fmt.Fprintf(&sb, "%d", b.Fthrough.ID)
		_, _ = sb.WriteString("\n")
	}

	return sb.String()
}

// getBlock retrieves the block associated with an instruction. It checks both
// the leader and edge metadata to find the block. If neither is found, it
// returns nil, indicating that the instruction forms neither the start nor end
// of a basic block.
func getBlock(ins *asm.Instruction) *Block {
	l := getLeaderMeta(ins)
	if l != nil {
		return l.block
	}

	e := getEdgeMeta(ins)
	if e != nil {
		return e.block
	}

	return nil
}

// Blocks is a list of basic blocks.
type Blocks []*Block

func (bl Blocks) count() uint64 {
	return uint64(len(bl))
}

func (bl *Blocks) add(b *Block) {
	if b == nil {
		return
	}

	b.ID = uint64(bl.count())
	*bl = append(*bl, b)
}

func (bl Blocks) first() *Block {
	if len(bl) == 0 {
		return nil
	}
	return bl[0]
}

func (bl Blocks) String() string {
	return bl.Dump(nil)
}

func (bl Blocks) Dump(insns asm.Instructions) string {
	var sb strings.Builder
	for _, block := range bl {
		_, _ = fmt.Fprintf(&sb, "\n=== Block %d ===\n", block.ID)
		_, _ = sb.WriteString(block.Dump(insns))
		_, _ = sb.WriteString("\n")
	}
	return sb.String()
}

// MakeBlocks returns a list of basic blocks of instructions that are always
// executed together. Multiple calls on the same insns will return the same
// Blocks object.
//
// Blocks are created by finding branches and jump targets in the given insns
// and cutting up the instruction stream accordingly.
func MakeBlocks(insns asm.Instructions) (Blocks, error) {
	if len(insns) == 0 {
		return nil, errors.New("insns is empty, cannot compute blocks")
	}

	if blocks := loadBlocks(insns); blocks != nil {
		return blocks, nil
	}

	blocks, err := computeBlocks(insns)
	if err != nil {
		return nil, fmt.Errorf("computing blocks: %w", err)
	}

	if err := storeBlocks(insns, blocks); err != nil {
		return nil, fmt.Errorf("storing blocks: %w", err)
	}

	return blocks, nil
}

// computeBlocks computes the basic blocks from the given instruction stream.
func computeBlocks(insns asm.Instructions) (Blocks, error) {
	if err := markBranches(insns); err != nil {
		return nil, fmt.Errorf("marking branches: %w", err)
	}

	blocks, callers, err := allocateBlocks(insns)
	if err != nil {
		return nil, fmt.Errorf("allocating blocks: %w", err)
	}

	if err := connectBlocks(blocks, insns); err != nil {
		return nil, fmt.Errorf("connecting blocks: %w", err)
	}

	callers.connect(blocks)

	return blocks, nil
}

// blocksKey is used to store Blocks in an instruction's metadata.
type blocksKey struct{}

// storeBlocks associates the given Blocks with the first instruction in the
// given insns.
//
// If insns is empty, does nothing.
func storeBlocks(insns asm.Instructions, bl Blocks) error {
	if len(insns) == 0 {
		return errors.New("insns is empty, cannot store Blocks")
	}

	insns[0].Metadata.Set(blocksKey{}, bl)

	return nil
}

// loadBlocks retrieves the Blocks associated with the first instruction in the
// given insns.
//
// If no Blocks is present, returns nil.
func loadBlocks(insns asm.Instructions) Blocks {
	if len(insns) == 0 {
		return nil
	}

	blocks, ok := insns[0].Metadata.Get(blocksKey{}).(Blocks)
	if !ok {
		return nil
	}

	return blocks
}

// markBranches identifies all jump targets in the instruction stream and marks
// branch and fallthrough edges accordingly.
//
// It performs two passes over the instruction stream: the first pass identifies
// all branch instructions and their raw jump targets, while the second pass
// resolves these raw targets to actual instruction pointers.
func markBranches(insns asm.Instructions) error {
	var targets rawTargets

	i := insns.Iterate()
	for i.Next() {
		// Set a leader on symbols, as they mark the start of functions.
		if sym := i.Ins.Symbol(); sym != "" {
			setLeader(i.Ins)
		}

		switch op := i.Ins.OpCode.JumpOp(); op {
		// No branch, ignore instruction.
		case asm.InvalidJumpOp, asm.Call:
			continue

		// There may be more instructions or another program after an exit. Emit an
		// edge with no branch or fallthrough and a leader on the next instruction,
		// if any.
		case asm.Exit:
			setEdgeExit(i.Ins, next(i, insns))

		// Regular branching instructions.
		default:
			raw, err := jumpTarget(i.Offset, i.Ins)
			if err != nil {
				return fmt.Errorf("determine jump target instruction offset: %w", err)
			}

			setBranchFallthrough(i.Ins, next(i, insns))

			// Queue the target by its raw instruction offset be updated with a branch
			// instruction pointer during a second pass since we cannot perform random
			// lookups of instructions by their raw offsets.
			targets.add(i.Ins, raw)
		}
	}

	// Second pass for resolving jumps to their target instructions. This can only
	// be done after all raw jump offsets have been identified, since jumps can be
	// forward or backward.
	i = insns.Iterate()
	for i.Next() {
		// Map the raw instruction offset to its logical instruction. In case of a
		// jump to the first instruction, the target has no prior instruction and
		// tgtPrev will be nil.
		targets.resolve(i.Offset, i.Ins, previous(i, insns))
	}

	return nil
}

// allocateBlocks returns a list of blocks based on leaders and edges identified
// in prior stages. It creates a new block whenever it encounters a leader
// instruction and finalizes the current one when it reaches an edge
// instruction. No blocks are pointing to each other yet, this is done in a
// subsequent step.
func allocateBlocks(insns asm.Instructions) (Blocks, bpfCallers, error) {
	if len(insns) == 0 {
		return nil, nil, errors.New("insns is empty, cannot allocate blocks")
	}

	// Expect at least one block.
	blocks := make(Blocks, 0, 1)
	callers := make(bpfCallers)

	var block *Block
	i := insns.Iterate()
	for i.Next() {
		// Roll over to the next block if this is a leader.
		if nextBlock := maybeAllocateBlock(i); nextBlock != nil {
			block = nextBlock
			blocks.add(block)
		}

		// Record function references in the current block.
		callers.record(i.Ins, block)

		// Finalize the block if we've reached an edge.
		maybeFinalizeBlock(block, i)
	}

	if blocks.count() == 0 {
		return nil, nil, errors.New("no blocks created, this is a bug")
	}

	if start := blocks.first().Start; start != 0 {
		return nil, nil, fmt.Errorf("first block starts at instruction index %d; this could be a bug, or the first insn is not a symbol", start)
	}

	return blocks, callers, nil
}

// maybeAllocateBlock allocates a new block for the instruction pointed to by
// the iterator if it is a leader instruction. If the instruction is not a
// leader, it returns nil. This is used to start a new basic block when
// encountering a leader instruction in the instruction stream.
func maybeAllocateBlock(i *asm.InstructionIterator) *Block {
	l := getLeaderMeta(i.Ins)
	if l == nil {
		return nil
	}
	l.block = &Block{
		sym:   i.Ins.Symbol(),
		Start: i.Index,
		Raw:   i.Offset,
	}
	return l.block
}

// maybeFinalizeBlock finalizes the current block by setting its end index and
// associating it with the edge metadata if the instruction is an edge.
// If the instruction is not an edge or the given block is nil, it does nothing.
func maybeFinalizeBlock(blk *Block, i *asm.InstructionIterator) {
	e := getEdgeMeta(i.Ins)
	if e == nil {
		return
	}
	if blk == nil {
		return
	}
	blk.End = i.Index
	e.block = blk
}

// connectBlocks connects the blocks in the given block list by setting their
// predecessors, branch and fallthrough targets based on the relationships
// between instructions identified in prior steps. Assumes that blocks have been
// allocated and that the leaders and edges have been tagged.
func connectBlocks(blocks Blocks, insns asm.Instructions) error {
	if blocks.count() == 0 {
		return errors.New("no blocks to connect, this is a bug")
	}

	// Wire all blocks together by setting their predecessors, branch and
	// fallthrough targets.
	for _, blk := range blocks {
		// Predecessors of the first instruction are the block's predecessors.
		leader := blk.leader(insns)
		if leader == nil {
			return fmt.Errorf("block %d has no leader", blk.ID)
		}

		blk.Predecessors = make([]*Block, 0, len(leader.predecessors))
		for _, pi := range leader.predecessors {
			b := getBlock(pi)
			if b == nil {
				return fmt.Errorf("predecessor instruction %v has no block", pi)
			}
			blk.Predecessors = append(blk.Predecessors, b)
		}

		// Branch/fthrough targets of the last instruction are the block's branch
		// and fallthrough targets.
		edge := blk.edge(insns)
		if edge == nil {
			return fmt.Errorf("block %d has no edge", blk.ID)
		}

		if edge.branch != nil {
			// If the edge has a branch target, set it as the block's branch target.
			b := getBlock(edge.branch)
			if b == nil {
				return fmt.Errorf("branch target %v has no block", edge.branch)
			}
			blk.Branch = b
		}

		if edge.fthrough != nil {
			// If the edge has a fallthrough target, set it as the block's fallthrough
			// target.
			b := getBlock(edge.fthrough)
			if b == nil {
				return fmt.Errorf("fallthrough target %v has no block", edge.fthrough)
			}
			blk.Fthrough = b
		}
	}

	return nil
}
