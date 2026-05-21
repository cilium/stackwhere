// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"fmt"
	"slices"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func branchingProg(tb testing.TB, n int) asm.Instructions {
	tb.Helper()

	// A program that ends up being cut into n blocks.
	orig := make(asm.Instructions, 0, n)
	for i := range n - 1 {
		ins := asm.JEq.Imm(asm.R0, int32(i), "")
		ins.Offset = 0
		orig = append(orig, ins)
	}
	orig[0] = orig[0].WithSymbol("prog")
	orig = append(orig, asm.Return())

	return orig
}

func callingProg(tb testing.TB, n int) asm.Instructions {
	tb.Helper()

	// Each function call results in a new block.
	// Exit is in its own block at the end of the program.
	// Each function gets a block as well.
	orig := make(asm.Instructions, 0, (n*3)+1)
	for i := range n {
		orig = append(orig, asm.Call.Label(fmt.Sprintf("fn%d", i)))
	}
	orig[0] = orig[0].WithSymbol("prog")
	orig = append(orig, asm.Return())

	for i := range n {
		fn := []asm.Instruction{
			asm.Mov.Imm(asm.R0, int32(i)).WithSymbol(fmt.Sprintf("fn%d", i)),
			asm.Return(),
		}
		orig = append(orig, fn...)
	}

	return orig
}

func TestMakeBlocksSimple(t *testing.T) {
	// A valid program with no branches.
	insns := asm.Instructions{
		asm.Mov.Imm32(asm.R0, 0).WithSymbol("prog"),
		asm.Return(),
	}

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 1, b.count())

	block := b.first()
	assert.EqualValues(t, 0, block.ID)
	assert.Equal(t, 0, block.Start)
	assert.Equal(t, 1, block.End)
	assert.Empty(t, block.Predecessors)
	assert.Nil(t, block.Branch)
	assert.Nil(t, block.Fthrough)

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestMakeBlocksManyBranches(t *testing.T) {
	insns := branchingProg(t, 1000)

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 1000, b.count())

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestMakeBlocksCalls(t *testing.T) {
	// A valid program with calls.
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0).WithSymbol("prog"),
		asm.Call.Label("fn"),
		asm.Return(),
		asm.Mov.Imm32(asm.R0, 0).WithSymbol("fn"),
		asm.Return(),
	}

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	require.Len(t, b, 2)

	blk := b.first()
	assert.Empty(t, blk.Predecessors)
	assert.Nil(t, blk.Fthrough)
	assert.Nil(t, blk.Branch)
	assert.Equal(t, 0, blk.Start)
	assert.Equal(t, 2, blk.End)

	blk = b[1]
	assert.Empty(t, blk.Predecessors)
	assert.Nil(t, blk.Fthrough)
	assert.Nil(t, blk.Branch)
	assert.Equal(t, 3, blk.Start)
	assert.Equal(t, 4, blk.End)

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestMakeBlocksManyCalls(t *testing.T) {
	insns := callingProg(t, 100)

	b, err := MakeBlocks(insns)
	require.NoError(t, err)
	require.Len(t, b, 101)

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestBlocksDump(t *testing.T) {
	insns := branchingProg(t, 100)

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	// Dump the blocks to a string and make sure it doesn't panic.
	dump := b.Dump(insns)

	assert.NotEmpty(t, dump)
}

func BenchmarkComputeBlocks(b *testing.B) {
	b.ReportAllocs()

	// Program with a 1000 branches resulting in 1000 blocks.
	orig := branchingProg(b, 1000)

	for b.Loop() {
		b.StopTimer()
		insns := slices.Clone(orig)
		b.StartTimer()

		if _, err := computeBlocks(insns); err != nil {
			b.Fatal("Error making block list:", err)
		}
	}
}

func BenchmarkComputeBlocksCalls(b *testing.B) {
	b.ReportAllocs()

	// Program with 500 calls to 500 functions, resulting in 1000 blocks (plus 1
	// for Exit).
	orig := callingProg(b, 500)

	for b.Loop() {
		b.StopTimer()
		insns := slices.Clone(orig)
		b.StartTimer()

		if _, err := computeBlocks(insns); err != nil {
			b.Fatal("Error making block list:", err)
		}
	}
}
