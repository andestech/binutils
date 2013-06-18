#objdump:  -d
#name: nds32 jump branch instructions
#as: -mbaseline=v3 -mall-ext

.*:     file format .*

Disassembly of section .text:
00000000 <foo>:
.*.*.*0:.*.*.*65.*20.*04.*02.*.*.*.*.*mfsr.*\$r18,\$core_id
.*.*.*4:.*.*.*65.*c6.*50.*03.*.*.*.*.*mtsr.*\$fp,\$bpam4
.*.*.*8:.*.*.*4a.*00.*05.*00.*.*.*.*.*jr.itoff.*\$r1
.*.*.*c:.*.*.*4a.*00.*07.*00.*.*.*.*.*jr.toff.*\$r1
.*.*10:.*.*.*4b.*e0.*05.*01.*.*.*.*.*jral.iton.*\$lp,\$r1
.*.*14:.*.*.*4a.*10.*09.*01.*.*.*.*.*jral.iton.*\$r1,\$r2
.*.*18:.*.*.*4b.*e0.*07.*01.*.*.*.*.*jral.ton.*\$lp,\$r1
.*.*1c:.*.*.*4a.*10.*0b.*01.*.*.*.*.*jral.ton.*\$r1,\$r2
.*.*20:.*.*.*64.*03.*00.*6e.*.*.*.*.*tlbop.*\$r6,rwritelock
