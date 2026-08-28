// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stackview

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestStackUsageFromDirectMemoryAccesses(t *testing.T) {
	tests := []struct {
		name  string
		insns asm.Instructions
		want  int64
	}{
		{
			name: "stack store",
			insns: asm.Instructions{
				asm.StoreMem(asm.R10, -8, asm.R0, asm.Word),
			},
			want: 8,
		},
		{
			name: "stack load rounded to slot",
			insns: asm.Instructions{
				asm.LoadMem(asm.R1, asm.R10, -12, asm.Word),
			},
			want: 16,
		},
		{
			name: "deepest stack access",
			insns: asm.Instructions{
				asm.StoreMem(asm.R10, -8, asm.R0, asm.Word),
				asm.StoreImm(asm.R10, -20, 0, asm.Word),
			},
			want: 24,
		},
		{
			name: "non-stack memory",
			insns: asm.Instructions{
				asm.StoreMem(asm.R1, -32, asm.R0, asm.Word),
				asm.LoadMem(asm.R0, asm.R1, -32, asm.Word),
			},
		},
		{
			name: "non-negative stack offset",
			insns: asm.Instructions{
				asm.StoreMem(asm.R10, 8, asm.R0, asm.Word),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stackUsageFromDirectMemoryAccesses(tt.insns); got != tt.want {
				t.Fatalf("unexpected stack usage: got %d want %d", got, tt.want)
			}
		})
	}
}
