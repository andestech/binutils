#objdump: -d --prefix-addresses
#name: nds32 convert lwi45.fe to lwi
#as: -O1

# Test lsi instructions

.*:     file format .*

Disassembly of section .text:
0+0000 <[^>]*> addi \$r8,\$r7,#0x4
0+0004 <[^>]*> lwi \$r0,\[\$r8\+\#\-4\]
0+0008 <[^>]*> addi333 \$r6,\$r6,#0x4
0+000a <[^>]*> nop16
