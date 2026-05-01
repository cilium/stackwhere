package dwarf

import (
	dbgDwarf "debug/dwarf"
)

// Re-export some of the DWARF constants and types that we use in multiple packages, so that we don't have to import
// the debug/dwarf package in those packages.

var (
	AttrLocation = dbgDwarf.AttrLocation
	AttrName     = dbgDwarf.AttrName
	AttrInline   = dbgDwarf.AttrInline
	AttrType     = dbgDwarf.AttrType
)

var (
	TagVariable        = dbgDwarf.TagVariable
	TagFormalParameter = dbgDwarf.TagFormalParameter
	TagSubprogram      = dbgDwarf.TagSubprogram
)
