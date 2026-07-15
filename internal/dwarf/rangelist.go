package dwarf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/cilium/stackwhere/internal/dwarf/leb128"
)

type rangeListHeader struct {
	unitLength          uint64
	version             uint16
	addrSize            uint8
	segmentSelectorSize uint8
	offsetEntryCount    uint32
}

type RangeListTable struct {
	hdr     rangeListHeader
	offsets []uint64
	entries map[uint64]RangeListEntry
}

type RangeListEntry struct {
	BaseAddressIdx uint64
	Ranges         []Range
}

type Range struct {
	Start uint64
	End   uint64
}

type rangelistDescriptorCode byte

const (
	DW_RLE_end_of_list   rangelistDescriptorCode = 0x00
	DW_RLE_base_addressx rangelistDescriptorCode = 0x01
	// DW_RLE_startx_endx      = 0x02
	DW_RLE_startx_length rangelistDescriptorCode = 0x03
	DW_RLE_offset_pair   rangelistDescriptorCode = 0x04
	// DW_RLE_base_address = 0x05
	// DW_RLE_start_end     = 0x06
	// DW_RLE_start_length = 0x07
)

func NewRangeListTable(f *elf.File) (*RangeListTable, error) {
	sec := f.Section(".debug_rnglists")
	if sec == nil {
		return nil, nil
	}

	if f.Class != elf.ELFCLASS64 {
		// Code should work, but untested
		return nil, fmt.Errorf("unexpected 32-bit ELF file")
	}

	b, err := sec.Data()
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)

	list := RangeListTable{
		entries: make(map[uint64]RangeListEntry),
	}

	debugAddrs, err := readDebugAddrEntries(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read .debug_addr: %w", err)
	}

	var (
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

	off := uint64(12)
	if !_32bit {
		off += 8
	}

	if _32bit {
		offsets := make([]uint32, list.hdr.offsetEntryCount)
		if err := binary.Read(r, f.ByteOrder, &offsets); err != nil {
			return nil, err
		}
		off += uint64(uint64(unsafe.Sizeof(uint32(0))) * uint64(list.hdr.offsetEntryCount))

		list.offsets = make([]uint64, len(offsets))
		for i, off := range offsets {
			list.offsets[i] = uint64(off)
		}
	} else {
		offsets := make([]uint64, list.hdr.offsetEntryCount)
		if err := binary.Read(r, f.ByteOrder, &offsets); err != nil {
			return nil, err
		}
		off += uint64(uint64(unsafe.Sizeof(uint64(0))) * uint64(list.hdr.offsetEntryCount))
		list.offsets = offsets
	}

loop:
	for {
		entryOff := off
		var entry RangeListEntry
		currentBase := uint64(0)

		for {
			descriptorByte, err := r.ReadByte()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break loop
				}

				return nil, err
			}
			off++

			switch rangelistDescriptorCode(descriptorByte) {
			case DW_RLE_end_of_list:
				list.entries[entryOff] = entry
				continue loop
			case DW_RLE_base_addressx:
				var idx uint64
				var l uint32
				idx, l, err = leb128.DecodeUnsigned(r)
				if err != nil {
					return nil, fmt.Errorf("error parsing base addressx entry: %w", err)
				}
				off += uint64(l)
				entry.BaseAddressIdx = idx
				if idx < uint64(len(debugAddrs)) {
					currentBase = debugAddrs[idx]
				}
			case DW_RLE_startx_length:
				var startIdx, length uint64
				var l uint32
				startIdx, l, err = leb128.DecodeUnsigned(r)
				if err != nil {
					return nil, fmt.Errorf("error parsing startx length entry: %w", err)
				}
				off += uint64(l)

				length, l, err = leb128.DecodeUnsigned(r)
				if err != nil {
					return nil, fmt.Errorf("error parsing startx length entry: %w", err)
				}
				off += uint64(l)

				if startIdx >= uint64(len(debugAddrs)) {
					return nil, fmt.Errorf("startx length entry references invalid debug address index: %d", startIdx)
				}

				entry.Ranges = append(entry.Ranges, Range{
					Start: debugAddrs[startIdx],
					End:   debugAddrs[startIdx] + length,
				})
			case DW_RLE_offset_pair:
				var rng Range
				var l uint32
				var startOff, endOff uint64
				startOff, l, err = leb128.DecodeUnsigned(r)
				if err != nil {
					return nil, fmt.Errorf("error parsing offset pair entry: %w", err)
				}
				off += uint64(l)

				endOff, l, err = leb128.DecodeUnsigned(r)
				if err != nil {
					return nil, fmt.Errorf("error parsing offset pair entry: %w", err)
				}
				off += uint64(l)

				rng.Start = currentBase + startOff
				rng.End = currentBase + endOff
				entry.Ranges = append(entry.Ranges, rng)
			default:
				return nil, fmt.Errorf("unsupported rangelist descriptor code: %x", descriptorByte)
			}
		}
	}

	return &list, nil
}

// readDebugAddrEntries reads the address entries from the .debug_addr section.
// It returns a slice of addresses indexed by their position in the table,
// or nil if the section is absent.
func readDebugAddrEntries(f *elf.File) ([]uint64, error) {
	sec := f.Section(".debug_addr")
	if sec == nil {
		return nil, nil
	}

	b, err := sec.Data()
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)

	// Parse DWARF unit_length to determine 32-bit vs 64-bit DWARF format.
	var ulen uint32
	if err := binary.Read(r, f.ByteOrder, &ulen); err != nil {
		return nil, fmt.Errorf("reading .debug_addr unit_length: %w", err)
	}

	hdrSize := 8 // 32-bit DWARF: 4 (unit_length) + 2 (version) + 1 (addr_size) + 1 (segment_selector_size)
	if ulen == 0xffffffff {
		// 64-bit DWARF format: skip the 8-byte extended length.
		var ulen64 uint64
		if err := binary.Read(r, f.ByteOrder, &ulen64); err != nil {
			return nil, fmt.Errorf("reading .debug_addr extended unit_length: %w", err)
		}
		hdrSize = 16 // 4 + 8 + 2 + 1 + 1
	}

	var version uint16
	if err := binary.Read(r, f.ByteOrder, &version); err != nil {
		return nil, fmt.Errorf("reading .debug_addr version: %w", err)
	}

	var addrSize uint8
	if err := binary.Read(r, f.ByteOrder, &addrSize); err != nil {
		return nil, fmt.Errorf("reading .debug_addr addr_size: %w", err)
	}

	// Skip segment_selector_size.
	if _, err := r.ReadByte(); err != nil {
		return nil, fmt.Errorf("reading .debug_addr segment_selector_size: %w", err)
	}

	if addrSize == 0 {
		return nil, nil
	}

	remaining := len(b) - hdrSize
	if remaining <= 0 {
		return nil, nil
	}

	count := remaining / int(addrSize)
	addrs := make([]uint64, count)
	for i := range addrs {
		switch addrSize {
		case 8:
			var addr uint64
			if err := binary.Read(r, f.ByteOrder, &addr); err != nil {
				return nil, fmt.Errorf("reading .debug_addr entry: %w", err)
			}
			addrs[i] = addr
		case 4:
			var addr uint32
			if err := binary.Read(r, f.ByteOrder, &addr); err != nil {
				return nil, fmt.Errorf("reading .debug_addr entry: %w", err)
			}
			addrs[i] = uint64(addr)
		default:
			return nil, fmt.Errorf("unsupported .debug_addr address size: %d", addrSize)
		}
	}

	return addrs, nil
}
