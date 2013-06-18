#objdump:  -d
#name: nds32 jump branch instructions
#as:

.*:     file format .*

Disassembly of section .text:
00000000 <foo>:
.*0:.*48 00 00 00.*j.*
.*4:.*49 00 00 00.*jal.*
.*8:.*4a 00 00 00.*jr.*
.*c:.*4a 00 00 20.*ret.*
.*10:.*4b e0 00 01.*jral.*
.*14:.*4a 00 04 01.*jral.*
.*18:.*4c 00 80 00.*beq.*
.*1c:.*4c 00 c0 00.*bne.*
.*20.*:.*4e 02 00 00.*beqz.*
.*24.*:.*4e 03 00 00.*bnez.*
.*28.*:.*4e 04 00 00.*bgez.*
.*2c.*:.*4e 05 00 00.*bltz.*
.*30.*:.*4e 06 00 00.*bgtz.*
.*34.*:.*4e 07 00 00.*blez.*
.*38.*:.*4e 0c 00 00.*bgezal.*
.*3c.*:.*4e 0d 00 00.*bltzal.*
