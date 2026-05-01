package dwarf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/stackwhere/internal/dwarf/leb128"
	"github.com/cilium/stackwhere/internal/dwarf/op"
)

type loclistHdr struct {
	unitLength          uint64
	version             uint16
	addrSize            uint8
	segmentSelectorSize uint8
	offsetEntryCount    uint32
}

type LoclistTable struct {
	hdr     loclistHdr
	offsets []uint64
	raw     []byte
}

type loclistDescriptorCode byte

const (
	DW_LLE_end_of_list   loclistDescriptorCode = 0x00
	DW_LLE_base_addressx loclistDescriptorCode = 0x01
	// DW_LLE_startx_endx      loclistDescriptor = 0x02
	// DW_LLE_startx_length    loclistDescriptor = 0x03
	DW_LLE_offset_pair loclistDescriptorCode = 0x04
	// DW_LLE_default_location loclistDescriptor = 0x05
	// DW_LLE_base_address     loclistDescriptor = 0x06
	// DW_LLE_start_end        loclistDescriptor = 0x07
	DW_LLE_start_length loclistDescriptorCode = 0x08
)

type LoclistEntry interface {
	_loclistEntry()
}

type LLEBaseAddressX struct {
	debugAddrIndex uint64
}

func (d LLEBaseAddressX) _loclistEntry() {}

type LLEOffsetPair struct {
	offset1 uint64
	offset2 uint64
	ops     []op.Operation
}

func (d LLEOffsetPair) Ops() []op.Operation {
	return d.ops
}

func (d LLEOffsetPair) _loclistEntry() {}

type LLEStartLength struct {
	start  uint64
	length uint64
}

func (d LLEStartLength) _loclistEntry() {}

type Loclist struct {
	entries []LoclistEntry
}

func (l *Loclist) Entries() []LoclistEntry {
	return l.entries
}

func (l *LoclistTable) Dump() {
	for i, offset := range l.offsets {
		loclist, err := l.Loclist(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Loclist %d (offset %#x):\n", i, offset)
			fmt.Fprintf(os.Stderr, "  <error parsing loclist: %v>\n", err)
			continue
		}

		fmt.Printf("Loclist %d (offset %#x):\n", i, offset)
		for _, entry := range loclist.entries {
			switch e := entry.(type) {
			case LLEBaseAddressX:
				fmt.Printf("  DW_LLE_base_addressx: debug_addr index %d\n", e.debugAddrIndex)
			case LLEOffsetPair:
				fmt.Printf("  DW_LLE_offset_pair: offset1 %#x, offset2 %#x, ops %v\n", e.offset1, e.offset2, e.ops)
			case LLEStartLength:
				fmt.Printf("  DW_LLE_start_length: start %#x, length %#x\n", e.start, e.length)
			default:
				fmt.Printf("  unknown entry type %T\n", e)
			}
		}
	}
}

func (l *LoclistTable) Loclist(i int) (*Loclist, error) {
	if i >= len(l.offsets) {
		return nil, fmt.Errorf("loclist index out of range")
	}

	offset := l.offsets[i]
	r := bytes.NewReader(l.raw[offset:])

	var list Loclist

loop:
	for {
		descriptorByte, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		var entry LoclistEntry
		switch loclistDescriptorCode(descriptorByte) {
		case DW_LLE_end_of_list:
			break loop
		case DW_LLE_base_addressx:
			var baseAddrX LLEBaseAddressX
			baseAddrX.debugAddrIndex, _, err = leb128.DecodeUnsigned(r)
			if err != nil {
				return nil, fmt.Errorf("error parsing base addressx entry: %w", err)
			}
			entry = baseAddrX
		case DW_LLE_offset_pair:
			var offsetPair LLEOffsetPair
			offsetPair.offset1, _, err = leb128.DecodeUnsigned(r)
			if err != nil {
				return nil, fmt.Errorf("error parsing offset pair entry: %w", err)
			}

			offsetPair.offset2, _, err = leb128.DecodeUnsigned(r)
			if err != nil {
				return nil, fmt.Errorf("error parsing offset pair entry: %w", err)
			}

			opsLen, _, err := leb128.DecodeUnsigned(r)
			if err != nil {
				return nil, fmt.Errorf("error parsing offset pair entry: %w", err)
			}

			opsData := make([]byte, opsLen)
			if _, err := r.Read(opsData); err != nil {
				return nil, err
			}

			ops, err := op.Parse(opsData)
			if err != nil {
				return nil, err
			}
			offsetPair.ops = ops

			entry = offsetPair
		default:
			return nil, fmt.Errorf("unsupported loclist descriptor code: %x", descriptorByte)
		}

		list.entries = append(list.entries, entry)
	}

	return &list, nil
}

func NewLoclistTable(f *elf.File) (*LoclistTable, error) {
	sec := f.Section(".debug_loclists")
	if sec == nil {
		return nil, nil
	}

	if f.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("unexpected 32-bit ELF file")
	}

	b, err := sec.Data()
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)

	var (
		list   LoclistTable
		ulen   uint32
		_32bit bool
	)

	if err := binary.Read(r, f.ByteOrder, &ulen); err != nil {
		return nil, err
	}
	if ulen == 0xffffffff {
		var ulen64 uint64
		if err := binary.Read(r, f.ByteOrder, &ulen64); err != nil {
			return nil, err
		}
		list.hdr.unitLength = ulen64
		_32bit = false
	} else {
		list.hdr.unitLength = uint64(ulen)
		_32bit = true
	}

	if err := binary.Read(r, f.ByteOrder, &list.hdr.version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, f.ByteOrder, &list.hdr.addrSize); err != nil {
		return nil, err
	}
	if err := binary.Read(r, f.ByteOrder, &list.hdr.segmentSelectorSize); err != nil {
		return nil, err
	}
	if err := binary.Read(r, f.ByteOrder, &list.hdr.offsetEntryCount); err != nil {
		return nil, err
	}

	if _32bit {
		list.raw = b[12:]
	} else {
		list.raw = b[20:]
	}

	if _32bit {
		offsets := make([]uint32, list.hdr.offsetEntryCount)
		if err := binary.Read(r, f.ByteOrder, &offsets); err != nil {
			return nil, err
		}
		for _, o := range offsets {
			list.offsets = append(list.offsets, uint64(o))
		}
	} else {
		if err := binary.Read(r, f.ByteOrder, &list.offsets); err != nil {
			return nil, err
		}
	}

	return &list, nil
}
