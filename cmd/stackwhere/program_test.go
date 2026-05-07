package main

import (
	"testing"

	"github.com/cilium/stackwhere/internal/dwarf"
)

func TestGetStackSlotUsage(t *testing.T) {
	tree, err := dwarf.NewDWARFTree("../../testdata/basic.o")
	if err != nil {
		t.Fatalf("failed to parse DWARF data: %v", err)
	}

	stackUsage := getStackSlotUsage(tree, "cil_entry")
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
			found[slot.name] = slot.byteSize
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
