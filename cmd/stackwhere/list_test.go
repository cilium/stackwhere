package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/stackwhere/internal/dwarf"
)

func TestGetStackSlotUsageFromDWARF(t *testing.T) {
	tree, err := dwarf.NewDWARFTree("../../testdata/basic.o")
	if err != nil {
		t.Fatalf("failed to parse DWARF data: %v", err)
	}

	subProgs := tree.ByType(dwarf.TagSubprogram)
	idx := slices.IndexFunc(subProgs, func(n *dwarf.Node) bool {
		return n.Name() == "cil_entry"
	})
	if idx == -1 {
		t.Fatalf("failed to find subprogram node for cil_entry")
	}

	stackUsage := stackSlotsFromDWARFVars(subProgs[idx])
	if len(stackUsage) != 3 {
		t.Fatalf("expected 3 stack slots, got %d", len(stackUsage))
	}

	// Verify each stack slot group contains expected slots
	slotGroups := []struct {
		index    int
		expected map[string]int64
	}{
		{
			index: 0,
			expected: map[string]int64{
				"a": 32,
				"b": 32,
				"c": 32,
			},
		},
		{
			index: 1,
			expected: map[string]int64{
				"two_inlined_a": 16,
				"two_inlined_b": 16,
				"two_inlined_c": 16,
			},
		},
		{
			index: 2,
			expected: map[string]int64{
				"one_inlined_d": 8,
			},
		},
	}

	for _, group := range slotGroups {
		found := make(map[string]int64)
		for _, slot := range stackUsage[group.index] {
			found[slot.Name] = slot.ByteSize
		}

		// Check all expected slots are present with correct size
		for name, expectedSize := range group.expected {
			actualSize, ok := found[name]
			if !ok {
				t.Errorf("slot group %d: expected slot %q not found", group.index, name)
				continue
			}
			if actualSize != expectedSize {
				t.Errorf("slot group %d: slot %q has size %d, expected %d", group.index, name, actualSize, expectedSize)
			}
			delete(found, name)
		}

		// Check no unexpected slots are present
		if len(found) > 0 {
			t.Errorf("slot group %d: unexpected slots found: %v", group.index, found)
		}
	}
}

func TestGetStackSlotUsageFromInsns(t *testing.T) {
	tree, err := dwarf.NewDWARFTree("../../testdata/spill.o")
	if err != nil {
		t.Fatalf("failed to parse DWARF data: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("../../testdata/spill.o")
	if err != nil {
		t.Fatalf("failed to load collection spec: %v", err)
	}

	subProgs := tree.ByType(dwarf.TagSubprogram)
	idx := slices.IndexFunc(subProgs, func(n *dwarf.Node) bool {
		return n.Name() == "cil_entry"
	})
	if idx == -1 {
		t.Fatalf("failed to find subprogram node for cil_entry")
	}

	fn := bpfFn{
		fn:    btf.FuncMetadata(&spec.Programs["cil_entry"].Instructions[0]),
		insns: spec.Programs["cil_entry"].Instructions,
	}

	stackUsage := stackSlotsFromInsns(fn, subProgs[idx])
	if len(stackUsage) != 1 {
		t.Fatalf("expected 1 stack slot group, got %d", len(stackUsage))
	}

	// Verify each stack slot group contains expected slots
	slotGroups := []struct {
		index    int
		expected map[string]int64
	}{
		{
			index: 0,
			expected: map[string]int64{
				"r2": -1,
			},
		},
	}

	for _, group := range slotGroups {
		found := make(map[string]int64)
		for _, slot := range stackUsage[group.index] {
			found[slot.Name] = slot.ByteSize
		}

		// Check all expected slots are present with correct size
		for name, expectedSize := range group.expected {
			actualSize, ok := found[name]
			if !ok {
				t.Errorf("slot group %d: expected slot %q not found", group.index, name)
				continue
			}
			if actualSize != expectedSize {
				t.Errorf("slot group %d: slot %q has size %d, expected %d", group.index, name, actualSize, expectedSize)
			}
			delete(found, name)
		}

		// Check no unexpected slots are present
		if len(found) > 0 {
			t.Errorf("slot group %d: unexpected slots found: %v", group.index, found)
		}
	}
}

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

func TestListCollectionWritesToConfiguredOutput(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/basic.o"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, "56 bytes - cil_entry") {
		t.Fatalf("expected collection output in configured writer, got %q", got)
	}
}

func TestListProgramWritesToConfiguredOutput(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/basic.o", "cil_entry"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, "R10-0:") {
		t.Fatalf("expected program output in configured writer, got %q", got)
	}
	if !strings.Contains(got, "32 - a @") {
		t.Fatalf("expected stack slot details in configured writer, got %q", got)
	}
}
