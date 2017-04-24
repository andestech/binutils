#objdump:  -d
#name: nds32 reduce register instructions
#as: -mreduced-regs

.*:     file format .*

Disassembly of section .text:
00000000 <foo>:
.*.*.*0:.*3a.*ff.*bc.*04.*.*lmw.bim.*\$r15,\[\$sp\],\$r15,#0x0.*.*.*.*!.*\{\$r15\}
.*.*.*4:.*3a.*5f.*9c.*3c.*.*smw.adm.*\$r5,\[\$sp\],\$r7,#0x0.*.*.*.*!.*\{\$r5~\$r7\}
.*.*.*8:.*3a.*ff.*bc.*3c.*.*smw.adm.*\$r15,\[\$sp\],\$r15,#0x0.*.*.*.*!.*\{\$r15\}
.*.*.*c:.*3a.*5f.*9c.*04.*.*lmw.bim.*\$r5,\[\$sp\],\$r7,#0x0.*.*.*.*!.*\{\$r5~\$r7\}
.*.*10:.*3a.*ff.*bc.*3c.*.*smw.adm.*\$r15,\[\$sp\],\$r15,#0x0.*.*.*.*!.*\{\$r15\}
