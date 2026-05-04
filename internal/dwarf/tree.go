package dwarf

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/cilium/stackwhere/internal/dwarf/op"
)

func NewDWARFTree(path string) (*Tree, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		_ = r.Close()
	}()
	return newDWARFTreeReader(r)
}

func newDWARFTreeReader(fileReader io.ReaderAt) (*Tree, error) {
	obj, err := elf.NewFile(fileReader)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}

	dbg, err := dwarfData(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DWARF data: %w", err)
	}

	llt, err := NewLoclistTable(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to create loclist table: %w", err)
	}

	tree := newTree(llt)
	var cur *Node

	r := dbg.Reader()
	for entry, err := r.Next(); entry != nil; entry, err = r.Next() {
		if err != nil {
			return nil, fmt.Errorf("failed to read DWARF entry: %w", err)
		}

		if entry.Tag == 0 {
			cur = cur.parent
			continue
		}

		n := newNode(tree, entry)
		if cur == nil {
			if entry.Tag != dwarf.TagCompileUnit {
				return nil, fmt.Errorf("unexpected root entry with tag %s", entry.Tag)
			}

			tree.root = n
			cur = n

			lr, err := dbg.LineReader(entry)
			if err != nil {
				return nil, fmt.Errorf("failed to create line reader: %w", err)
			}

			tree.files = lr.Files()
		} else {
			cur.children = append(cur.children, n)
			n.parent = cur

			if entry.Children {
				cur = n
			}
		}

		tree.AddToIndex(n)
	}

	return tree, nil
}

type Tree struct {
	root   *Node
	index  map[dwarf.Offset]*Node
	byType map[dwarf.Tag][]*Node

	files []*dwarf.LineFile
	llt   *LoclistTable
}

func newTree(llt *LoclistTable) *Tree {
	return &Tree{
		index:  make(map[dwarf.Offset]*Node),
		byType: make(map[dwarf.Tag][]*Node),
		files:  nil,
		llt:    llt,
	}
}

func (t *Tree) AddToIndex(n *Node) {
	t.index[n.Entry().Offset] = n
	if _, ok := t.byType[n.Entry().Tag]; !ok {
		t.byType[n.Entry().Tag] = []*Node{}
	}
	t.byType[n.Entry().Tag] = append(t.byType[n.Entry().Tag], n)
}

func (t *Tree) ByType(tag dwarf.Tag) []*Node {
	return t.byType[tag]
}

func (t *Tree) Dump() {
	t.root.Dump(0)
}

func newNode(tree *Tree, entry *dwarf.Entry) *Node {
	return &Node{tree: tree, entry: entry}
}

type Node struct {
	tree     *Tree
	entry    *dwarf.Entry
	parent   *Node
	children []*Node
}

func (n *Node) Entry() *dwarf.Entry {
	return n.entry
}

func (n *Node) Parent() *Node {
	return n.parent
}

func (n *Node) Dump(indent int) {
	fmt.Printf("%s%#x: %s\n", strings.Repeat(" ", indent), n.Entry().Offset, n.Entry().Tag)
	for _, attr := range n.Entry().Field {
		if attr.Attr == dwarf.AttrLocation {
			switch attr.Class {
			case dwarf.ClassExprLoc:
				ops, err := n.Location()
				if err != nil {
					fmt.Printf("%s %s: <invalid location expression: %v>\n", strings.Repeat(" ", indent), attr.Attr, err)
				} else {
					fmt.Printf("%s %s:\n", strings.Repeat(" ", indent), attr.Attr)
					for _, op := range ops {
						fmt.Printf("%s    %s\n", strings.Repeat(" ", indent), op)
					}
				}
			case dwarf.ClassLocList:
				loclist, err := n.LocationList()
				if err != nil {
					fmt.Printf("%s %s: <invalid location list: %v>\n", strings.Repeat(" ", indent), attr.Attr, err)
				}
				fmt.Printf("%s %s:\n", strings.Repeat(" ", indent), attr.Attr)
				if loclist == nil {
					fmt.Printf("%s    <no location list>\n", strings.Repeat(" ", indent))
				} else {
					for _, entry := range loclist.entries {
						switch e := entry.(type) {
						case LLEBaseAddressX:
							fmt.Printf("%s    DW_LLE_base_addressx: debug_addr index %d\n", strings.Repeat(" ", indent), e.debugAddrIndex)
						case LLEOffsetPair:
							fmt.Printf("%s    DW_LLE_offset_pair: offset1 %#x, offset2 %#x, ops:\n", strings.Repeat(" ", indent), e.offset1, e.offset2)
							for _, op := range e.ops {
								fmt.Printf("%s         %s\n", strings.Repeat(" ", indent), op)
							}
						case LLEStartLength:
							fmt.Printf("%s    DW_LLE_start_length: start %#x, length %#x\n", strings.Repeat(" ", indent), e.start, e.length)
						default:
							fmt.Printf("%s    unknown entry type %T\n", strings.Repeat(" ", indent), e)
						}
					}
				}
			}
			continue
		}

		if attr.Attr == dwarf.AttrType {
			typeEntry := n.Type()
			if typeEntry == nil {
				fmt.Printf("%s %s: <invalid type reference>\n", strings.Repeat(" ", indent), attr.Attr)
			} else {
				fmt.Printf("%s %s: %s\n", strings.Repeat(" ", indent), attr.Attr, typeEntry.Name())
				typeEntry.Dump(indent + 1)
			}
			continue
		}

		if attr.Attr == dwarf.AttrDeclFile {
			fmt.Printf("%s %s: %s\n", strings.Repeat(" ", indent), attr.Attr, n.tree.files[attr.Val.(int64)].Name)
			continue
		}

		fmt.Printf("%s %s: %#v\n", strings.Repeat(" ", indent), attr.Attr, spew.NewFormatter(attr.Val))
		if attr.Attr == dwarf.AttrAbstractOrigin {
			originEntry, ok := n.tree.index[attr.Val.(dwarf.Offset)]
			if ok {
				originEntry.Dump(indent + 1)
			}
		}
	}
	for _, c := range n.children {
		c.Dump(indent + 1)
	}
}

// The abstract origin attribute is used to deduplicate common attributes between multiple entries.
// For example, when a function is inlined into multiple places, there will be multiple entries with the same name,
// type, and location, but different locations in the code where they are inlined.
// These entries can point to a single abstract origin entry that has the common attributes, and then only have the
// location attribute that is different between them.
func (n *Node) AbstractOrigin() *Node {
	abstractOrigin := n.Entry().Val(dwarf.AttrAbstractOrigin)
	if abstractOrigin == nil {
		return nil
	}

	originEntry, ok := n.tree.index[abstractOrigin.(dwarf.Offset)]
	if !ok {
		return nil
	}

	return originEntry
}

func (n *Node) Name() string {
	name := n.Entry().Val(dwarf.AttrName)
	if name != nil {
		return name.(string)
	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.Name()
	}

	return ""
}

// Returns the location as bytes, see 2.6.1 Location Expressions in the DWARF 5 spec for details on the format of these bytes.
func (n *Node) rawLocation() []byte {
	location := n.Entry().Val(dwarf.AttrLocation)
	if location != nil {
		if locationBytes, ok := location.([]byte); ok {
			return locationBytes
		}

		return nil
	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.rawLocation()
	}

	return nil
}

// Returns the size of type in bytes.
func (n *Node) ByteSize() int64 {
	if n.Entry().Tag == dwarf.TagPointerType {
		// Assume 64-bit pointers if byte size is not specified.
		return 8
	}

	byteSize := n.Entry().Val(dwarf.AttrByteSize)
	if byteSize != nil {
		return byteSize.(int64)
	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.ByteSize()
	}

	if typ := n.Type(); typ != nil {
		return typ.ByteSize()
	}

	return 0
}

// Returns the location as a list of DWARF operations, or nil if there is no location.
// Sometimes a location is static an can be resolved. Sometimes a location is dynamic and depends on the context in
// which it is evaluated, in which case runtime info such as register values is needed to resolve it.
func (n *Node) Location() ([]op.Operation, error) {
	ops := n.rawLocation()
	if ops == nil {
		return nil, nil
	}

	return op.Parse(ops)
}

// Returns the location as a list of location list entries, or nil if there is no location list. Location lists are used
// when the location of a variable changes over the course of the program, for example when a variable is optimized to
// live in a register for part of the program and on the stack for another part of the program.
func (n *Node) LocationList() (*Loclist, error) {
	loclistOffset := n.Entry().Val(dwarf.AttrLocation)
	if loclistOffset == nil {
		return nil, nil
	}

	offset, ok := loclistOffset.(uint64)
	if !ok {
		return nil, nil
	}

	return n.tree.llt.Loclist(int(offset))
}

// Returns the type of this entry, or nil if there is no type.
func (n *Node) Type() *Node {
	typ := n.Entry().Val(dwarf.AttrType)
	if typ != nil {
		typeEntry, ok := n.tree.index[typ.(dwarf.Offset)]
		if !ok {
			return nil
		}

		return typeEntry

	}

	abstractOrigin := n.AbstractOrigin()
	if abstractOrigin != nil {
		return abstractOrigin.Type()
	}

	return nil
}

// Returns the file and line number of this entry, or an empty string if there is no file and line number.
func (n *Node) FileCol() string {
	fileIndex := n.Entry().Val(dwarf.AttrDeclFile)
	if fileIndex == nil {
		abstractOrigin := n.AbstractOrigin()
		if abstractOrigin != nil {
			return abstractOrigin.FileCol()
		}

		return ""
	}
	file := n.tree.files[fileIndex.(int64)]

	fileLine := n.Entry().Val(dwarf.AttrDeclLine)
	if fileLine != nil {
		fileCol := n.Entry().Val(dwarf.AttrDeclColumn)
		if fileCol != nil {
			return fmt.Sprintf("%s:%d:%d", file.Name, fileLine.(int64), fileCol.(int64))
		}

		return fmt.Sprintf("%s:%d", file.Name, fileLine.(int64))
	}

	return file.Name
}

func VisitPrefixOrder(n *Node, f func(*Node)) {
	f(n)
	for _, c := range n.children {
		VisitPrefixOrder(c, f)
	}
}

// Extract all relevant sections from the ELF file and create a dwarf.Data object from them.
func dwarfData(f *elf.File) (*dwarf.Data, error) {
	dwarfSuffix := func(s *elf.Section) string {
		switch {
		case strings.HasPrefix(s.Name, ".debug_"):
			return s.Name[7:]
		case strings.HasPrefix(s.Name, ".zdebug_"):
			return s.Name[8:]
		default:
			return ""
		}
	}

	// There are many DWARF sections, but these are the ones
	// the debug/dwarf package started with.
	var dat = map[string][]byte{"abbrev": nil, "info": nil, "str": nil, "line": nil, "ranges": nil}
	for _, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; !ok {
			continue
		}
		b, err := s.Data()
		if err != nil {
			return nil, err
		}
		dat[suffix] = b
	}

	d, err := dwarf.New(dat["abbrev"], nil, nil, dat["info"], dat["line"], nil, dat["ranges"], dat["str"])
	if err != nil {
		return nil, err
	}

	// Look for DWARF4 .debug_types sections and DWARF5 sections.
	for i, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; ok {
			// Already handled.
			continue
		}

		b, err := s.Data()
		if err != nil {
			return nil, err
		}

		if suffix == "types" {
			if err := d.AddTypes(fmt.Sprintf("types-%d", i), b); err != nil {
				return nil, err
			}
		} else {
			if err := d.AddSection(".debug_"+suffix, b); err != nil {
				return nil, err
			}
		}
	}

	return d, nil
}
