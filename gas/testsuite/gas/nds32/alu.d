#objdump:  -d
#name: nds32 alu instructions
#as: -mdx-regs -mbaseline=v3 -mall-ext

.*:     file format .*

Disassembly of section .text:
00000000 <foo>:
.*.*.*0:.*.*.*50.*00.*80.*02.*.*.*.*.*addi.*\$r0,\$r1,#0x2
.*.*.*4:.*.*.*52.*00.*80.*02.*.*.*.*.*subri.*\$r0,\$r1,#0x2
.*.*.*8:.*.*.*54.*00.*80.*02.*.*.*.*.*andi.*\$r0,\$r1,#0x2
.*.*.*c:.*.*.*58.*00.*80.*02.*.*.*.*.*ori.*\$r0,\$r1,#0x2
.*.*10:.*.*.*56.*00.*80.*02.*.*.*.*.*xori.*\$r0,\$r1,#0x2
.*.*14:.*.*.*5c.*00.*80.*02.*.*.*.*.*slti.*\$r0,\$r1,#0x2
.*.*18:.*.*.*5e.*00.*80.*02.*.*.*.*.*sltsi.*\$r0,\$r1,#0x2
.*.*1c:.*.*.*44.*00.*00.*02.*.*.*.*.*movi.*\$r0,#0x2
.*.*20:.*.*.*46.*00.*00.*02.*.*.*.*.*sethi.*\$r0,#0x2
.*.*24:.*.*.*40.*00.*88.*00.*.*.*.*.*add.*\$r0,\$r1,\$r2
.*.*28:.*.*.*40.*00.*88.*01.*.*.*.*.*sub.*\$r0,\$r1,\$r2
.*.*2c:.*.*.*40.*00.*88.*02.*.*.*.*.*and.*\$r0,\$r1,\$r2
.*.*30:.*.*.*40.*00.*88.*05.*.*.*.*.*nor.*\$r0,\$r1,\$r2
.*.*34:.*.*.*40.*00.*88.*04.*.*.*.*.*or.*\$r0,\$r1,\$r2
.*.*38:.*.*.*40.*00.*88.*03.*.*.*.*.*xor.*\$r0,\$r1,\$r2
.*.*3c:.*.*.*40.*00.*88.*06.*.*.*.*.*slt.*\$r0,\$r1,\$r2
.*.*40:.*.*.*40.*00.*88.*07.*.*.*.*.*slts.*\$r0,\$r1,\$r2
.*.*44:.*.*.*40.*00.*88.*18.*.*.*.*.*sva.*\$r0,\$r1,\$r2
.*.*48:.*.*.*40.*00.*88.*19.*.*.*.*.*svs.*\$r0,\$r1,\$r2
.*.*4c:.*.*.*54.*00.*80.*ff.*.*.*.*.*andi.*\$r0,\$r1,#0xff
.*.*50:.*.*.*40.*00.*80.*13.*.*.*.*.*zeh.*\$r0,\$r1
.*.*54:.*.*.*40.*00.*80.*14.*.*.*.*.*wsbh.*\$r0,\$r1
.*.*58:.*.*.*40.*00.*84.*08.*.*.*.*.*slli.*\$r0,\$r1,#0x1
.*.*5c:.*.*.*40.*00.*84.*09.*.*.*.*.*srli.*\$r0,\$r1,#0x1
.*.*60:.*.*.*40.*00.*84.*0a.*.*.*.*.*srai.*\$r0,\$r1,#0x1
.*.*64:.*.*.*40.*00.*84.*0b.*.*.*.*.*rotri.*\$r0,\$r1,#0x1
.*.*68:.*.*.*40.*00.*88.*0c.*.*.*.*.*sll.*\$r0,\$r1,\$r2
.*.*6c:.*.*.*40.*00.*88.*0d.*.*.*.*.*srl.*\$r0,\$r1,\$r2
.*.*70:.*.*.*40.*00.*88.*0e.*.*.*.*.*sra.*\$r0,\$r1,\$r2
.*.*74:.*.*.*40.*00.*88.*0f.*.*.*.*.*rotr.*\$r0,\$r1,\$r2
.*.*78:.*.*.*42.*00.*88.*24.*.*.*.*.*mul.*\$r0,\$r1,\$r2
.*.*7c:.*.*.*42.*00.*88.*28.*.*.*.*.*mults64.*\$d0,\$r1,\$r2
.*.*80:.*.*.*42.*00.*88.*29.*.*.*.*.*mult64.*\$d0,\$r1,\$r2
.*.*84:.*.*.*42.*00.*04.*2a.*.*.*.*.*madds64.*\$d0,\$r0,\$r1
.*.*88:.*.*.*42.*00.*04.*2b.*.*.*.*.*madd64.*\$d0,\$r0,\$r1
.*.*8c:.*.*.*42.*00.*04.*2c.*.*.*.*.*msubs64.*\$d0,\$r0,\$r1
.*.*90:.*.*.*42.*00.*04.*2d.*.*.*.*.*msub64.*\$d0,\$r0,\$r1
.*.*94:.*.*.*42.*00.*88.*31.*.*.*.*.*mult32.*\$d0,\$r1,\$r2
.*.*98:.*.*.*42.*00.*88.*33.*.*.*.*.*madd32.*\$d0,\$r1,\$r2
.*.*9c:.*.*.*42.*00.*88.*35.*.*.*.*.*msub32.*\$d0,\$r1,\$r2
.*.*a0:.*.*.*42.*0f.*80.*20.*.*.*.*.*mfusr.*\$r0,\$pc
.*.*a4:.*.*.*42.*0f.*80.*21.*.*.*.*.*mtusr.*\$r0,\$pc
.*.*a8:.*42 01 0c 2f.*div \$d0,\$r2,\$r3
.*.*ac:.*42 01 0c 2e .*divs \$d0,\$r2,\$r3
