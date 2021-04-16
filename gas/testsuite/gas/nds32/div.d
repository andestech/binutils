#objdump: -d
#name: Option checking: -mdiv (Enable divide instruction)
#as: -mdiv -mdx-regs

.*:     file format .*

Disassembly of section .text:
00000000 <foo>:
.*0:.*42.*00.*88.*2f.*div.*\$d0,.*\$r1,.*\$r2
.*4:.*42.*00.*88.*2e.*divs.*\$d0,.*\$r1,.*\$r2
.*8:.*40.*01.*0c.*37.*divr.*\$r0,.*\$r1,.*\$r2,.*\$r3
.*c:.*40.*01.*0c.*36.*divsr.*\$r0,.*\$r1,.*\$r2,.*\$r3
