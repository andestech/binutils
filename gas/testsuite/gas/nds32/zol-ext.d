#objdump: -d
#name: Option checking: -mzol-ext (Enable hardware loop extension)
#as: -mzol-ext -mdsp-ext

.*:     file format .*

Disassembly of section .text:

00000000.*<foo>:
.*.*.*0:.*4e.*10.*7f.*ff.*.*mtlbi.*fffe.*<foo\+0xfffe>
.*.*.*4:.*4e.*20.*00.*01.*.*mtlei.*6.*<foo\+0x6>
