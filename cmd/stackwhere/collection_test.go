package main

import (
	"testing"

	"github.com/cilium/stackwhere/internal/dwarf"
)

func TestGetProgramStackUsage(t *testing.T) {
	tree, err := dwarf.NewDWARFTree("../../testdata/basic.o")
	if err != nil {
		t.Fatalf("failed to parse DWARF data: %v", err)
	}

	stackUsagePerProgram := map[string]int64{}
	for _, prog := range tree.ByType(dwarf.TagSubprogram) {
		if !isBPFProgram(prog) {
			continue
		}

		stackUsagePerProgram[prog.Name()] = getProgramStackUsage(prog)
	}

	stackUsage := stackUsagePerProgram["cil_entry"]
	expectedStackUsage := int64(56)
	if stackUsage != expectedStackUsage {
		t.Errorf("expected stack usage %d, got %d", expectedStackUsage, stackUsage)
	}
}
