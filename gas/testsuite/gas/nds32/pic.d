#objdump: -d
#name: -mpic (Generate pic code for pseudo instruction)
#as: -mpic

.*:     file format .*

Disassembly.*of.*section.*.text:

00000000.*<foo>:
.*.*.*0:.*46.*f0.*00.*00.*.*sethi.*\$r15,#0x0
.*.*.*4:.*58.*f7.*80.*00.*.*ori.*\$r15,\$r15,#0x0
.*.*.*8:.*40.*f7.*f4.*00.*.*add.*\$r15,\$r15,\$gp
.*.*.*c:.*4a.*00.*3c.*00.*.*jr.*\$r15
