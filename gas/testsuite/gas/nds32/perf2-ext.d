#objdump: -d
#name: Option checking: =mperf2-ext (Enable performance extension V2 instructions)
#as: -mperf2-ext

.*:     file format .*

Disassembly of section .text:

00000000.*<foo>:
.*.*.*0:.*42.*11.*0c.*0c.*bse.*\$r1,\$r2,\$r3
.*.*.*4:.*42.*11.*0c.*0d.*bsp.*\$r1,\$r2,\$r3
.*.*.*8:.*70.*11.*0c.*00.*pbsad.*\$r1,\$r2,\$r3
.*.*.*c:.*70.*11.*0c.*01.*pbsada.*\$r1,\$r2,\$r3
