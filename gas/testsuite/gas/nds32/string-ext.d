#objdump: -d
#name: Option checking: -mstring-ext (Enable string extension instructions)
#as: -mstring-ext

.*:     file format .*

Disassembly of section .text:

00000000.*<foo>:
.*.*.*0:.*42.*11.*0c.*0e.*.*.*.*.*ffb.*\$r1,\$r2,\$r3
.*.*.*4:.*42.*11.*00.*ce.*.*.*.*.*ffbi.*\$r1,\$r2,#0x1
.*.*.*8:.*42.*11.*0c.*0f.*.*.*.*.*ffmism.*\$r1,\$r2,\$r3
.*.*.*c:.*42.*11.*0c.*4f.*.*.*.*.*flmism.*\$r1,\$r2,\$r3