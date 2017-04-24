#objdump: -dr --prefix-addresses
#name: Option checking: -mno-fp-as-gp
#as: -mno-fp-as-gp

.*:     file format .*

Disassembly.*of.*section.*.text:
00000000.*<[^>]*>.*sethi.*\$fp,.*
.*.*.*0:.*R_NDS32_HI20_RELA.*_FP_BASE_
.*.*.*0:.*R_NDS32_LOADSTORE.*
.*.*.*0:.*R_NDS32_RELAX_ENTRY.*
00000004.*<[^>]*>.*ori.*\$fp,\$fp,.*
.*.*.*4:.*R_NDS32_LO12S0_RELA.*_FP_BASE_
.*.*.*4:.*R_NDS32_INSN16.*
00000008.*<[^>]*>.*sethi.*\$r15,.*
.*.*.*8:.*R_NDS32_HI20_RELA.*
.*.*.*8:.*R_NDS32_LOADSTORE.*
0000000c.*<[^>]*>.*lwi.*\$r0,\[\$r15.*\]
.*.*.*c:.*R_NDS32_LO12S2_RELA.*
.*.*.*c:.*R_NDS32_INSN16.*
00000010.*<[^>]*>.*sethi.*\$r15,.*
.*.*.*10:.*R_NDS32_HI20_RELA.*
.*.*.*10:.*R_NDS32_LOADSTORE.*
00000014.*<[^>]*>.*lwi.*\$r1,\[\$r15.*\]
.*.*.*14:.*R_NDS32_LO12S2_RELA.*
.*.*.*14:.*R_NDS32_INSN16.*
00000018.*<[^>]*>.*sethi.*\$r15,.*
.*.*.*18:.*R_NDS32_HI20_RELA.*
.*.*.*18:.*R_NDS32_LOADSTORE.*
0000001c.*<[^>]*>.*lwi.*\$r2,\[\$r15.*\]
.*.*.*1c:.*R_NDS32_LO12S2_RELA.*
.*.*.*1c:.*R_NDS32_INSN16.*
00000020.*<[^>]*>.*sethi.*\$r15,.*
.*.*.*20:.*R_NDS32_HI20_RELA.*
.*.*.*20:.*R_NDS32_LOADSTORE.*
00000024.*<[^>]*>.*lwi.*\$r3,\[\$r15.*\]
.*.*.*24:.*R_NDS32_LO12S2_RELA.*
.*.*.*24:.*R_NDS32_INSN16.*
00000028.*<[^>]*>.*sethi.*\$r15,.*
.*.*.*28:.*R_NDS32_HI20_RELA.*
.*.*.*28:.*R_NDS32_LOADSTORE.*
0000002c.*<[^>]*>.*lwi.*\$r4,\[\$r15.*\]
.*.*.*2c:.*R_NDS32_LO12S2_RELA.*
.*.*.*2c:.*R_NDS32_INSN16.*