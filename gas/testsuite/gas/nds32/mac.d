#objdump: -d
#name: Option checking: -mmac (Enable multiply (with accumulation) instructions support)
#as: -mmac -mdx-regs

.*:     file format .*

Disassembly of section .text:

00000000.*<foo>:
.*.*.*0:.*42.*00.*04.*2a.*.*madds64.*\$d0,\$r0,\$r1
.*.*.*4:.*42.*00.*04.*2b.*.*madd64.*\$d0,\$r0,\$r1
.*.*.*8:.*42.*00.*04.*2c.*.*msubs64.*\$d0,\$r0,\$r1
.*.*.*c:.*42.*00.*04.*2d.*.*msub64.*\$d0,\$r0,\$r1
.*.*10:.*42.*00.*88.*33.*.*madd32.*\$d0,\$r1,\$r2
.*.*14:.*42.*00.*88.*73.*.*maddr32.*\$r0,\$r1,\$r2
.*.*18:.*42.*00.*88.*35.*.*msub32.*\$d0,\$r1,\$r2
.*.*1c:.*42.*00.*88.*75.*.*msubr32.*\$r0,\$r1,\$r2
