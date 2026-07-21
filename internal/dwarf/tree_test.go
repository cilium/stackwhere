// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dwarf

import (
	"debug/dwarf"
	"testing"
)

func TestNodeLocationsUseCompilationUnitFiles(t *testing.T) {
	firstUnitFiles := []*dwarf.LineFile{{Name: "first.c"}}
	secondUnitFiles := []*dwarf.LineFile{{Name: "second.c"}}

	firstNode := &Node{
		entry: &dwarf.Entry{Field: []dwarf.Field{
			{Attr: dwarf.AttrDeclFile, Val: int64(0)},
			{Attr: dwarf.AttrDeclLine, Val: int64(7)},
			{Attr: dwarf.AttrCallFile, Val: int64(0)},
			{Attr: dwarf.AttrCallLine, Val: int64(9)},
		}},
		files: firstUnitFiles,
	}
	secondNode := &Node{
		entry: &dwarf.Entry{Field: []dwarf.Field{
			{Attr: dwarf.AttrDeclFile, Val: int64(0)},
			{Attr: dwarf.AttrDeclLine, Val: int64(11)},
			{Attr: dwarf.AttrCallFile, Val: int64(0)},
			{Attr: dwarf.AttrCallLine, Val: int64(13)},
		}},
		files: secondUnitFiles,
	}

	if got := firstNode.FileLineCol(); got != "first.c:7" {
		t.Fatalf("first node declaration location = %q, want %q", got, "first.c:7")
	}
	if got := firstNode.CallFileLineCol(); got != "first.c:9" {
		t.Fatalf("first node call location = %q, want %q", got, "first.c:9")
	}
	if got := secondNode.FileLineCol(); got != "second.c:11" {
		t.Fatalf("second node declaration location = %q, want %q", got, "second.c:11")
	}
	if got := secondNode.CallFileLineCol(); got != "second.c:13" {
		t.Fatalf("second node call location = %q, want %q", got, "second.c:13")
	}
}
