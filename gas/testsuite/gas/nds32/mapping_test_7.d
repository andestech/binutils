#objdump:  -d
#name: nds32 mapping 7
#as: -mel

.*:     file format .*

Disassembly of section .text:
00000000 <foo>:
.*.*.*0:.*40.*00.*00.*09.*.*nop
.*.*.*4:.*00.*00.*03.*00.*.*.word.*0x00030000
.*.*.*8:.*20.*00.*.*.*.*.*.*.*.*.short.*0x0020
.*.*.*a:.*01.*00.*.*.*.*.*.*.*.*.byte.*0x01
.*.*.*c:.*40.*00.*00.*09.*.*nop
