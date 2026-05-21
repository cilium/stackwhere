package main

import (
	"io"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/stackwhere/internal/analyze"
)

func runVisitor(t *testing.T, insns asm.Instructions) *visitor {
	t.Helper()

	blocks, err := analyze.MakeBlocks(insns)
	if err != nil {
		t.Fatalf("make blocks: %v", err)
	}

	v := &visitor{
		dbgWriter:       io.Discard,
		insns:           insns,
		reachableWrites: make(map[*analyze.Block][]rw),
		inStates:        make(map[*analyze.Block]state),
		outStates:       make(map[*analyze.Block]state),
		seenReads:       make(map[rw]struct{}),
		seenWrites:      make(map[rw]struct{}),
	}
	v.visit(blocks[0], state{stack: make(map[int16]stackState)})
	return v
}

func hasRW(items []rw, offset int16, raw asm.RawInstructionOffset) bool {
	for _, item := range items {
		if item.Offset == offset && item.RawIns == raw {
			return true
		}
	}
	return false
}

func TestVisitorRevisitsJoinWithDifferentIncomingState(t *testing.T) {
	branch := asm.JEq.Imm(asm.R0, 0, "")
	branch.Offset = 3
	branch = branch.WithSymbol("prog")
	jmpToJoin := asm.Ja.Label("")
	jmpToJoin.Offset = 1

	insns := asm.Instructions{
		branch,
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreMem(asm.R10, -8, asm.R1, asm.DWord),
		jmpToJoin,
		asm.Mov.Imm32(asm.R0, 0),
		asm.LoadMem(asm.R1, asm.R10, -8, asm.DWord),
		asm.Return(),
	}

	v := runVisitor(t, insns)

	if !hasRW(v.writes, -8, 2) {
		t.Fatalf("expected write at raw ins 2 for stack offset -8, got writes=%v", v.writes)
	}
	if !hasRW(v.reads, -8, 5) {
		t.Fatalf("expected read at join block (raw ins 5) for stack offset -8, got reads=%v", v.reads)
	}
}

func TestVisitorRevisitsLoopHeaderWhenStateChanges(t *testing.T) {
	branch := asm.JEq.Imm(asm.R0, 0, "")
	branch.Offset = 3
	branch = branch.WithSymbol("prog")
	jmpToLoopRead := asm.Ja.Label("")
	jmpToLoopRead.Offset = 2
	jmpNoWriteToLoopRead := asm.Ja.Label("")
	jmpNoWriteToLoopRead.Offset = 0
	backEdge := asm.Ja.Label("")
	backEdge.Offset = -7

	insns := asm.Instructions{
		branch,
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreMem(asm.R10, -8, asm.R1, asm.DWord),
		jmpToLoopRead,
		asm.Mov.Imm32(asm.R3, 0),
		jmpNoWriteToLoopRead,
		asm.LoadMem(asm.R2, asm.R10, -8, asm.DWord),
		backEdge,
		asm.Return(),
	}

	v := runVisitor(t, insns)

	if !hasRW(v.writes, -8, 2) {
		t.Fatalf("expected loop write at raw ins 2 for stack offset -8, got writes=%v", v.writes)
	}
	if !hasRW(v.reads, -8, 6) {
		t.Fatalf("expected read at loop join (raw ins 6) for stack offset -8, got reads=%v", v.reads)
	}
}

func TestLifetimeAddSortsAndUpdatesIntervals(t *testing.T) {
	lt := &Lifetime{}

	lt.Add(LTInterval(asm.RawInstructionOffset(1<<30), asm.RawInstructionOffset(1<<30)+2, false))
	lt.Add(LTInterval(2, 3, false))
	lt.Add(LTInterval(10, 15, false))
	lt.Add(LTInterval(10, 18, false))

	if len(lt.Intervals) != 3 {
		t.Fatalf("expected 3 intervals, got %d", len(lt.Intervals))
	}

	if lt.Intervals[0].Start != 2 || lt.Intervals[1].Start != 10 || lt.Intervals[2].Start != asm.RawInstructionOffset(1<<30) {
		t.Fatalf("intervals are not sorted by start: %+v", lt.Intervals)
	}

	if lt.Intervals[1].End != 18 {
		t.Fatalf("expected interval with start=10 to update end to 18, got %d", lt.Intervals[1].End)
	}
}

func TestGoAluOpDivisionAndModuloByZero(t *testing.T) {
	tests := []struct {
		name string
		op   asm.ALUOp
		b32  bool
	}{
		{name: "div 64", op: asm.Div, b32: false},
		{name: "div 32", op: asm.Div, b32: true},
		{name: "sdiv 64", op: asm.SDiv, b32: false},
		{name: "sdiv 32", op: asm.SDiv, b32: true},
		{name: "mod 64", op: asm.Mod, b32: false},
		{name: "mod 32", op: asm.Mod, b32: true},
		{name: "smod 64", op: asm.SMod, b32: false},
		{name: "smod 32", op: asm.SMod, b32: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := goAluOp(42, 0, tt.op, tt.b32)
			if err == nil {
				t.Fatalf("expected error for zero divisor with op=%v b32=%v", tt.op, tt.b32)
			}
		})
	}
}

func TestGoAluOpNegativeShiftUsesMaskedCount(t *testing.T) {
	res, err := goAluOp(1, -1, asm.LSh, true)
	if err != nil {
		t.Fatalf("unexpected error for LSh with negative shift: %v", err)
	}
	if res != int64(uint32(1)<<31) {
		t.Fatalf("unexpected LSh result: got %d", res)
	}

	res, err = goAluOp(int64(uint32(1)<<31), -1, asm.RSh, true)
	if err != nil {
		t.Fatalf("unexpected error for RSh with negative shift: %v", err)
	}
	if res != 1 {
		t.Fatalf("unexpected RSh result: got %d", res)
	}

	res, err = goAluOp(-8, -1, asm.ArSh, true)
	if err != nil {
		t.Fatalf("unexpected error for ArSh with negative shift: %v", err)
	}
	if res != -1 {
		t.Fatalf("unexpected ArSh result: got %d", res)
	}
}
