// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dwarf

import (
	"debug/dwarf"
	"slices"
	"testing"
)

func TestNormalizeCompileUnitFiles(t *testing.T) {
	tests := []struct {
		name     string
		unitName string
		compDir  string
		fileName string
		want     string
	}{
		{
			name:     "joined absolute path",
			unitName: "/src/basic.c",
			compDir:  "/go",
			fileName: "/go/src/basic.c",
			want:     "/src/basic.c",
		},
		{
			name:     "relative unit path",
			unitName: "src/basic.c",
			compDir:  "/go",
			fileName: "/go/src/basic.c",
			want:     "/go/src/basic.c",
		},
		{
			name:     "correct absolute path",
			unitName: "/src/basic.c",
			compDir:  "/go",
			fileName: "/src/basic.c",
			want:     "/src/basic.c",
		},
		{
			name:     "unrelated file",
			unitName: "/src/basic.c",
			compDir:  "/go",
			fileName: "/go/src/header.h",
			want:     "/go/src/header.h",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &dwarf.Entry{Field: []dwarf.Field{
				{Attr: dwarf.AttrName, Val: tt.unitName},
				{Attr: dwarf.AttrCompDir, Val: tt.compDir},
			}}
			file := &dwarf.LineFile{Name: tt.fileName}
			files := []*dwarf.LineFile{file}

			got := normalizeCompileUnitFiles(entry, files)
			if got[0].Name != tt.want {
				t.Fatalf("normalized file name = %q, want %q", got[0].Name, tt.want)
			}
			if file.Name != tt.fileName || !slices.Equal(files, []*dwarf.LineFile{file}) {
				t.Fatalf("normalizeCompileUnitFiles mutated its input")
			}
		})
	}
}

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
