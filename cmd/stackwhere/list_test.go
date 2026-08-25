package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/stackwhere/internal/stackview"
)

func hasSlot(slots [][]stackview.SlotUsage, wantName string, wantSize int64) bool {
	for _, group := range slots {
		for _, slot := range group {
			if slot.Name == wantName && slot.ByteSize == wantSize {
				return true
			}
		}
	}

	return false
}

func TestProgramDetailsFromDWARF(t *testing.T) {
	analyzer, err := stackview.NewAnalyzer("../../testdata/basic.o")
	if err != nil {
		t.Fatalf("failed to initialize analyzer: %v", err)
	}

	stackUsage, err := analyzer.ProgramDetails("cil_entry")
	if err != nil {
		t.Fatalf("failed to get program details: %v", err)
	}

	for _, want := range []struct {
		name string
		size int64
	}{
		{name: "a", size: 32},
		{name: "b", size: 32},
		{name: "c", size: 32},
		{name: "two_inlined_a", size: 16},
		{name: "two_inlined_b", size: 16},
		{name: "two_inlined_c", size: 16},
		{name: "one_inlined_d", size: 8},
	} {
		if !hasSlot(stackUsage, want.name, want.size) {
			t.Fatalf("expected to find slot %q (size %d) in program details", want.name, want.size)
		}
	}
}

func TestProgramDetailsFromInsns(t *testing.T) {
	analyzer, err := stackview.NewAnalyzer("../../testdata/spill.o")
	if err != nil {
		t.Fatalf("failed to initialize analyzer: %v", err)
	}

	stackUsage, err := analyzer.ProgramDetails("cil_entry")
	if err != nil {
		t.Fatalf("failed to get program details: %v", err)
	}

	if !hasSlot(stackUsage, "r2", -1) {
		t.Fatalf("expected to find inferred spill slot r2 with unknown byte size")
	}
}

func TestCollectionSummaryIncludesProgramUsage(t *testing.T) {
	analyzer, err := stackview.NewAnalyzer("../../testdata/basic.o")
	if err != nil {
		t.Fatalf("failed to initialize analyzer: %v", err)
	}

	var got int64
	found := false
	for _, prog := range analyzer.CollectionSummary() {
		if prog.Name != "cil_entry" {
			continue
		}

		got = prog.StackUsage
		found = true
		break
	}
	if !found {
		t.Fatalf("expected cil_entry in collection summary")
	}

	expectedStackUsage := int64(56)
	if got != expectedStackUsage {
		t.Errorf("expected stack usage %d, got %d", expectedStackUsage, got)
	}
}

func TestListCollectionIncludesInstructionOnlyStackUsage(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/noinline.o"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	if got := stdout.String(); !strings.Contains(got, "8 bytes - entry") {
		t.Fatalf("expected instruction-derived stack usage in collection output, got %q", got)
	}
}

func TestListCollectionSortsAfterInferringStackUsage(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/noinline.o", "-j"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	var got []stackview.ProgramStackUsage
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode JSON output: %v", err)
	}

	want := []stackview.ProgramStackUsage{
		{Name: "entry", StackUsage: 8},
		{Name: "z_known", StackUsage: 8},
		{Name: "helper", StackUsage: 0},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected JSON output: got %#v want %#v", got, want)
	}
}

func TestListCollectionIncludesVoidFunction(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/noinline.o"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	if got := stdout.String(); !strings.Contains(got, "0 bytes - helper") {
		t.Fatalf("expected void helper in collection output, got %q", got)
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
	if strings.Count(got, "16 - two_inlined_a @ /src/basic.c:81") != 1 {
		t.Fatalf("expected duplicate inline rows to be suppressed in default output, got %q", got)
	}
	if strings.Count(got, "16 - two_inlined_b @ /src/basic.c:75") != 1 {
		t.Fatalf("expected duplicate inline rows to be suppressed in default output, got %q", got)
	}
}

func TestListProgramReportsNoStackUsage(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/noinline.o", "helper"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	if got, want := stdout.String(), "No stack usage.\n"; got != want {
		t.Fatalf("expected explicit no-stack-usage output, got %q, want %q", got, want)
	}
}

func TestListProgramCallStackPreservesDistinctInlineCallSites(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/basic.o", "cil_entry", "--call-stack"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	got := stdout.String()
	if strings.Count(got, "16 - two_inlined_a @ /src/basic.c:81") != 2 {
		t.Fatalf("expected both inline call sites in call-stack output, got %q", got)
	}
	if !strings.Contains(got, "inlined_a @ /src/basic.c:93:9") || !strings.Contains(got, "inlined_a @ /src/basic.c:103:9") {
		t.Fatalf("expected both inline call stacks in output, got %q", got)
	}
}

func TestSortedProgramStackUsageOrdersEqualUsageByName(t *testing.T) {
	out := stackview.SortProgramStackUsage(map[string]int64{
		"beta":  16,
		"alpha": 16,
		"gamma": 24,
	})

	want := []stackview.ProgramStackUsage{
		{Name: "gamma", StackUsage: 24},
		{Name: "alpha", StackUsage: 16},
		{Name: "beta", StackUsage: 16},
	}

	if !slices.Equal(out, want) {
		t.Fatalf("unexpected sorted output: got %#v want %#v", out, want)
	}
}

func TestListCollectionJSONOrdersEqualUsageByName(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/equal.o", "-j"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	var got []stackview.ProgramStackUsage
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode JSON output: %v", err)
	}

	want := []stackview.ProgramStackUsage{
		{Name: "alpha", StackUsage: 16},
		{Name: "beta", StackUsage: 16},
	}

	if !slices.Equal(got, want) {
		t.Fatalf("unexpected JSON output: got %#v want %#v", got, want)
	}
}

func TestListProgramSupportsStartXLengthRangeLists(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"list", "../../testdata/noinline.o", "entry", "-j"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	var got [][]stackview.SlotUsage
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode JSON output: %v", err)
	}

	want := [][]stackview.SlotUsage{
		{
			{Offset: 4, Name: "r1", ByteSize: -1},
		},
	}
	if len(got) != len(want) || len(got[0]) != len(want[0]) ||
		got[0][0].Offset != want[0][0].Offset || got[0][0].Name != want[0][0].Name || got[0][0].ByteSize != want[0][0].ByteSize {
		t.Fatalf("unexpected JSON output: got %#v want %#v", got, want)
	}
}
