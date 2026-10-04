// Copyright (c) 2026 Eitanity Systems VCC. All rights reserved.
// Use of this source code is governed by the BSD-2-Clause licence in LICENSE.
//
// The type codes and table below are translated from file.h and apprentice.c,
// file 5.48, Copyright (c) Ian F. Darwin 1986-1995 (see COPYING).

package softmagic

import "github.com/eitanity/softmagic/internal/invariant"

// fileType is libmagic's FILE_* test type code. The numeric values are part
// of the entry sort: its tie-break compares them as bytes.
type fileType uint8

const (
	tInvalid     fileType = 0
	tByte        fileType = 1
	tShort       fileType = 2
	tDefault     fileType = 3
	tLong        fileType = 4
	tString      fileType = 5
	tDate        fileType = 6
	tBeShort     fileType = 7
	tBeLong      fileType = 8
	tBeDate      fileType = 9
	tLeShort     fileType = 10
	tLeLong      fileType = 11
	tLeDate      fileType = 12
	tPString     fileType = 13
	tLDate       fileType = 14
	tBeLDate     fileType = 15
	tLeLDate     fileType = 16
	tRegex       fileType = 17
	tBeString16  fileType = 18
	tLeString16  fileType = 19
	tSearch      fileType = 20
	tMeDate      fileType = 21
	tMeLDate     fileType = 22
	tMeLong      fileType = 23
	tQuad        fileType = 24
	tLeQuad      fileType = 25
	tBeQuad      fileType = 26
	tQDate       fileType = 27
	tLeQDate     fileType = 28
	tBeQDate     fileType = 29
	tQLDate      fileType = 30
	tLeQLDate    fileType = 31
	tBeQLDate    fileType = 32
	tFloat       fileType = 33
	tBeFloat     fileType = 34
	tLeFloat     fileType = 35
	tDouble      fileType = 36
	tBeDouble    fileType = 37
	tLeDouble    fileType = 38
	tBeID3       fileType = 39
	tLeID3       fileType = 40
	tIndirect    fileType = 41
	tQWDate      fileType = 42
	tLeQWDate    fileType = 43
	tBeQWDate    fileType = 44
	tName        fileType = 45
	tUse         fileType = 46
	tClear       fileType = 47
	tDer         fileType = 48
	tGUID        fileType = 49
	tLeGUID      fileType = 50
	tBeGUID      fileType = 51
	tOffset      fileType = 52
	tBeVarint    fileType = 53
	tLeVarint    fileType = 54
	tMSDOSDate   fileType = 55
	tLeMSDOSDate fileType = 56
	tBeMSDOSDate fileType = 57
	tMSDOSTime   fileType = 58
	tLeMSDOSTime fileType = 59
	tBeMSDOSTime fileType = 60
	tOctal       fileType = 61
	numTypes              = 62
)

// printf format class of a type's description (FILE_FMT_*).
type fmtClass uint8

const (
	fmtNone fmtClass = iota
	fmtNum
	fmtStr
	fmtQuad
	fmtFloat
	fmtDouble
)

// typeEntry is one row of apprentice.c's type_tbl; name matching is by
// prefix, in table order, exactly as get_type does it.
type typeEntry struct {
	name string
	typ  fileType
	fmt  fmtClass
}

// typeTables holds apprentice.c's type_tbl and special_tbl. They are
// built by newTypeTables for each Compile rather than held at package level
// (the module keeps no package-level mutable state).
type typeTables struct {
	types   [numTypes]typeEntry
	special [4]typeEntry
}

// newTypeTables returns the tables in the reference's declaration order,
// which get_type's prefix matching depends on.
func newTypeTables() typeTables {
	return typeTables{types: typeTableRows(), special: [4]typeEntry{
		{"der", tDer, fmtStr},
		{"name", tName, fmtStr},
		{"use", tUse, fmtStr},
		{"octal", tOctal, fmtStr},
	}}
}

// typeTableRows is apprentice.c's type_tbl in its declaration order.
func typeTableRows() [numTypes]typeEntry {
	return [numTypes]typeEntry{
		{"invalid", tInvalid, fmtNone}, {"byte", tByte, fmtNum},
		{"short", tShort, fmtNum}, {"default", tDefault, fmtNone},
		{"long", tLong, fmtNum}, {"string", tString, fmtStr},
		{"date", tDate, fmtStr}, {"beshort", tBeShort, fmtNum},
		{"belong", tBeLong, fmtNum}, {"bedate", tBeDate, fmtStr},
		{"leshort", tLeShort, fmtNum}, {"lelong", tLeLong, fmtNum},
		{"ledate", tLeDate, fmtStr}, {"pstring", tPString, fmtStr},
		{"ldate", tLDate, fmtStr}, {"beldate", tBeLDate, fmtStr},
		{"leldate", tLeLDate, fmtStr}, {"regex", tRegex, fmtStr},
		{"bestring16", tBeString16, fmtStr}, {"lestring16", tLeString16, fmtStr},
		{"search", tSearch, fmtStr}, {"medate", tMeDate, fmtStr},
		{"meldate", tMeLDate, fmtStr}, {"melong", tMeLong, fmtNum},
		{"quad", tQuad, fmtQuad}, {"lequad", tLeQuad, fmtQuad},
		{"bequad", tBeQuad, fmtQuad}, {"qdate", tQDate, fmtStr},
		{"leqdate", tLeQDate, fmtStr}, {"beqdate", tBeQDate, fmtStr},
		{"qldate", tQLDate, fmtStr}, {"leqldate", tLeQLDate, fmtStr},
		{"beqldate", tBeQLDate, fmtStr}, {"float", tFloat, fmtFloat},
		{"befloat", tBeFloat, fmtFloat}, {"lefloat", tLeFloat, fmtFloat},
		{"double", tDouble, fmtDouble}, {"bedouble", tBeDouble, fmtDouble},
		{"ledouble", tLeDouble, fmtDouble}, {"leid3", tLeID3, fmtNum},
		{"beid3", tBeID3, fmtNum}, {"indirect", tIndirect, fmtNum},
		{"qwdate", tQWDate, fmtStr}, {"leqwdate", tLeQWDate, fmtStr},
		{"beqwdate", tBeQWDate, fmtStr}, {"name", tName, fmtNone},
		{"use", tUse, fmtNone}, {"clear", tClear, fmtNone},
		{"der", tDer, fmtStr}, {"guid", tGUID, fmtStr},
		{"leguid", tLeGUID, fmtStr}, {"beguid", tBeGUID, fmtStr},
		{"offset", tOffset, fmtQuad}, {"bevarint", tBeVarint, fmtStr},
		{"levarint", tLeVarint, fmtStr}, {"msdosdate", tMSDOSDate, fmtStr},
		{"lemsdosdate", tLeMSDOSDate, fmtStr}, {"bemsdosdate", tBeMSDOSDate, fmtStr},
		{"msdostime", tMSDOSTime, fmtStr}, {"lemsdostime", tLeMSDOSTime, fmtStr},
		{"bemsdostime", tBeMSDOSTime, fmtStr}, {"octal", tOctal, fmtStr},
	}
}

// lookupType is get_type: the first table row whose name is a prefix of s.
// It returns the type and the number of bytes consumed, 0 when none matched.
func lookupType(table []typeEntry, s []byte) (fileType, int) {
	invariant.Check(len(table) > 0, "table has rows")
	for i := range table {
		if hasPrefix(s, table[i].name) {
			return table[i].typ, len(table[i].name)
		}
	}
	return tInvalid, 0
}

func hasPrefix(s []byte, p string) bool {
	if len(s) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if s[i] != p[i] {
			return false
		}
	}
	return true
}

// isString is file.h's IS_STRING.
func isString(t fileType) bool {
	switch t {
	case tString, tPString, tBeString16, tLeString16, tRegex, tSearch,
		tIndirect, tName, tUse, tOctal:
		return true
	default:
		return false
	}
}

// typeSize is apprentice.c's typesize; 0 means FILE_BADSIZE.
func typeSize(t fileType) int {
	switch t {
	case tByte:
		return 1
	case tShort, tLeShort, tBeShort, tMSDOSDate, tBeMSDOSDate, tLeMSDOSDate,
		tMSDOSTime, tBeMSDOSTime, tLeMSDOSTime:
		return 2
	case tLong, tLeLong, tBeLong, tMeLong,
		tDate, tLeDate, tBeDate, tMeDate, tLDate, tLeLDate, tBeLDate, tMeLDate,
		tFloat, tBeFloat, tLeFloat, tBeID3, tLeID3:
		return 4
	case tQuad, tBeQuad, tLeQuad, tQDate, tLeQDate, tBeQDate,
		tQLDate, tLeQLDate, tBeQLDate, tQWDate, tLeQWDate, tBeQWDate,
		tDouble, tBeDouble, tLeDouble, tOffset, tBeVarint, tLeVarint:
		return 8
	case tLeGUID, tBeGUID, tGUID:
		return 16
	default:
		return 0
	}
}

// formatClass is file_formats[t].
func formatClass(t fileType) fmtClass {
	switch {
	case t == tDefault || t == tName || t == tUse || t == tClear || t == tInvalid:
		return fmtNone
	case t == tQuad || t == tLeQuad || t == tBeQuad || t == tOffset:
		return fmtQuad
	case t == tFloat || t == tBeFloat || t == tLeFloat:
		return fmtFloat
	case t == tDouble || t == tBeDouble || t == tLeDouble:
		return fmtDouble
	case t == tByte || t == tShort || t == tLong || t == tBeShort || t == tBeLong ||
		t == tLeShort || t == tLeLong || t == tMeLong || t == tLeID3 || t == tBeID3 || t == tIndirect:
		return fmtNum
	case int(t) < numTypes:
		return fmtStr
	default:
		return fmtNone
	}
}

// typeName is file_names[t].
func typeName(t fileType) string {
	if int(t) >= numTypes {
		return "invalid"
	}
	rows := typeTableRows()
	return rows[t].name
}
