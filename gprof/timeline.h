#ifndef timeline_h
#define timeline_h
// ============================================================================
// timeline.h
// Copyright 2006 Andes Technology Corporation
//
// This file is part of GNU Binutils.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// ============================================================================

// data record types
#define PROFTYPE_FC1 0x11
#define PROFDLEN_FC1 17
#define PROFTYPE_FR1 0x12
#define PROFDLEN_FR1 17
#define PROFTYPE_FC2 0x21
#define PROFDLEN_FC2 18
#define PROFTYPE_FR2 0x22
#define PROFDLEN_FR2 18
#define PROFTYPE_BR2 0x23
#define PROFDLEN_BR2 18
#define PROFTYPE_FC3 0x31
#define PROFDLEN_FC3 10
#define PROFTYPE_FR3 0x32
#define PROFDLEN_FR3 10
#define PROFTYPE_BR3 0x33
#define PROFDLEN_BR3 10
#define PROFTYPE_MA3 0x34
#define PROFDLEN_MA3 12
#define PROFTYPE_OT3 0x35
#define PROFDLEN_OT3 5
#define PROFTYPE_FC6 0x61
#define PROFDLEN_FC6 43
#define PROFTYPE_FR6 0x62
#define PROFDLEN_FR6 43
#define PROFTYPE_FC7 0x71
#define PROFDLEN_FC7 68
#define PROFTYPE_FR7 0x72
#define PROFDLEN_FR7 68
#define PROFTYPE_FC8 0x81
#define PROFDLEN_FC8 94
#define PROFTYPE_FR8 0x82
#define PROFDLEN_FR8 94
#define PROFTYPE_FC9 0x91
#define PROFDLEN_FC9 72
#define PROFTYPE_FR9 0x92
#define PROFDLEN_FR9 72
#define PROFTYPE_BR9 0x93
#define PROFDLEN_BR9 72
#define PROFTYPE_DUMMY_FC1 0x1A
#define PROFTYPE_DUMMY_FR1 0x1B
#define PROFTYPE_DUMMY_FC2 0x2A
#define PROFTYPE_DUMMY_FR2 0x2B
#define PROFTYPE_DUMMY_FC3 0x3A
#define PROFTYPE_DUMMY_FR3 0x3B
#define PROFTYPE_DUMMY_FC6 0x6A
#define PROFTYPE_DUMMY_FR6 0x6B
#define PROFTYPE_DUMMY_FC7 0x7A
#define PROFTYPE_DUMMY_FR7 0x7B
#define PROFTYPE_DUMMY_FC8 0x8A
#define PROFTYPE_DUMMY_FR8 0x8B
#define PROFTYPE_DUMMY_FC9 0x9A
#define PROFTYPE_DUMMY_FR9 0x9B

#define PROFTYPE_OFF 0xC0
#define PROFDLEN_OFF 17
#define PROFTYPE_ON  0xC0
#define PROFDLEN_ON  18
#define PROFTYPE_ON1 0xC1
#define PROFTYPE_ON2 0xC2
#define PROFTYPE_ON3 0xC3
#define PROFTYPE_ON4 0xC4
#define PROFTYPE_ON5 0xC5
#define PROFTYPE_ON6 0xC6
#define PROFTYPE_ON7 0xC7
#define PROFTYPE_ON8 0xC8
#define PROFTYPE_ON9 0xC9
#define PROFTYPE_MOD 0xCF
#define PROFDLEN_MOD 14
#define PROFTYPE_NEW 0xF0
#define PROFDLEN_NEW 21
#define PROFTYPE_TCI 0xF1
#define PROFDLEN_TCI 25
#define PROFTYPE_TCU 0xFE
#define PROFDLEN_TCU 25
#define PROFTYPE_EOF 0xFF
#define PROFDLEN_EOF 1

extern int print_cgtimeline (void);
extern void print_bbtimeline (void);
extern void print_cacheusage (void);
extern int getMsgLen(char *, int);
#endif
