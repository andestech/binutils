#objdump:  -d
#name: nds32 16bit v2 instructions
#as: -m16bit-ext

.*:     file format .*

Disassembly of section .text:
00000000 <foo>:
.*.*.*0:.*.*.*ec.*73.*.*.*.*.*.*.*.*.*.*.*addi10.sp.*#0x73
.*.*.*2:.*.*.*f1.*56.*.*.*.*.*.*.*.*.*.*.*lwi37.sp.*\$r1,\[\+#0x158\]
.*.*.*4:.*.*.*f4.*89.*.*.*.*.*.*.*.*.*.*.*swi37.sp.*\$r4,\[\+#0x24\]
