#objdump: -d
#name: Option checking: -mfpu-dp-ext (Enable floating point double precision)
#as: -mfpu-dp-ext -mfpu-sp-ext

.*:     file format .*

Disassembly of section .text:

00000000.*<foo>:
.*.*.*0:.*6a.*00.*88.*08.*.*faddd.*\$fd0,\$fd1,\$fd2
.*.*.*4:.*6a.*00.*88.*48.*.*fsubd.*\$fd0,\$fd1,\$fd2
.*.*.*8:.*6a.*00.*8b.*08.*.*fmuld.*\$fd0,\$fd1,\$fd2
.*.*.*c:.*6a.*00.*8b.*48.*.*fdivd.*\$fd0,\$fd1,\$fd2
.*.*10:.*6a.*00.*87.*c8.*.*fsqrtd.*\$fd0,\$fd1
.*.*14:.*6a.*00.*89.*08.*.*fmaddd.*\$fd0,\$fd1,\$fd2
.*.*18:.*6a.*00.*89.*48.*.*fmsubd.*\$fd0,\$fd1,\$fd2
.*.*1c:.*6a.*00.*8a.*08.*.*fnmaddd.*\$fd0,\$fd1,\$fd2
.*.*20:.*6a.*00.*8a.*48.*.*fnmsubd.*\$fd0,\$fd1,\$fd2
.*.*24:.*6a.*00.*88.*0c.*.*fcmpeqd.*\$fs0,\$fd1,\$fd2
.*.*28:.*6a.*00.*88.*8c.*.*fcmpltd.*\$fs0,\$fd1,\$fd2
.*.*2c:.*6a.*00.*89.*0c.*.*fcmpled.*\$fs0,\$fd1,\$fd2
.*.*30:.*6a.*00.*89.*8c.*.*fcmpund.*\$fs0,\$fd1,\$fd2
.*.*34:.*6a.*00.*88.*4c.*.*fcmpeqd.e.*\$fs0,\$fd1,\$fd2
.*.*38:.*6a.*00.*88.*cc.*.*fcmpltd.e.*\$fs0,\$fd1,\$fd2
.*.*3c:.*6a.*00.*89.*4c.*.*fcmpled.e.*\$fs0,\$fd1,\$fd2
.*.*40:.*6a.*00.*89.*cc.*.*fcmpund.e.*\$fs0,\$fd1,\$fd2
.*.*44:.*6a.*00.*03.*01.*.*fmfcfg.*\$r0
.*.*48:.*6a.*00.*07.*01.*.*fmfcsr.*\$r0
.*.*4c:.*6a.*00.*07.*09.*.*fmtcsr.*\$r0
.*.*50:.*6a.*01.*80.*01.*.*fmfsr.*\$r0,\$fs3
.*.*54:.*6a.*01.*80.*09.*.*fmtsr.*\$r0,\$fs3
.*.*58:.*6a.*00.*97.*c8.*.*fabsd.*\$fd0,\$fd1
.*.*5c:.*6a.*00.*88.*c8.*.*fcpysd.*\$fd0,\$fd1,\$fd2
.*.*60:.*6a.*00.*88.*88.*.*fcpynsd.*\$fd0,\$fd1,\$fd2
.*.*64:.*6a.*00.*89.*c8.*.*fcmovzd.*\$fd0,\$fd1,\$fs2
.*.*68:.*6a.*00.*89.*88.*.*fcmovnd.*\$fd0,\$fd1,\$fs2
.*.*6c:.*6a.*00.*80.*41.*.*fmfdr.*\$r0,\$fd1
.*.*70:.*6a.*00.*80.*49.*.*fmtdr.*\$r0,\$fd1
.*.*74:.*6a.*00.*07.*02.*.*fls.*\$fs0,\[\$r0\+\(\$r1<<#0x3\)\]
.*.*78:.*6a.*00.*07.*82.*.*fls.bi.*\$fs0,\[\$r0\],\(\$r1<<#0x3\)
.*.*7c:.*30.*00.*03.*ff.*.*flsi.*\$fs0,\[\$r0\+#0xffc\]
.*.*80:.*30.*00.*13.*ff.*.*flsi.bi.*\$fs0,\[\$r0\],#0xffc
.*.*84:.*6a.*00.*05.*0a.*.*fss.*\$fs0,\[\$r0\+\(\$r1<<#0x1\)\]
.*.*88:.*6a.*00.*05.*8a.*.*fss.bi.*\$fs0,\[\$r0\],\(\$r1<<#0x1\)
.*.*8c:.*32.*00.*00.*01.*.*fssi.*\$fs0,\[\$r0\+#0x4\]
.*.*90:.*32.*00.*10.*01.*.*fssi.bi.*\$fs0,\[\$r0\],#0x4
.*.*94:.*6a.*00.*07.*03.*.*fld.*\$fd0,\[\$r0\+\(\$r1<<#0x3\)\]
.*.*98:.*6a.*00.*07.*83.*.*fld.bi.*\$fd0,\[\$r0\],\(\$r1<<#0x3\)
.*.*9c:.*34.*00.*03.*ff.*.*fldi.*\$fd0,\[\$r0\+#0xffc\]
.*.*a0:.*34.*00.*13.*ff.*.*fldi.bi.*\$fd0,\[\$r0\],#0xffc
.*.*a4:.*6a.*00.*05.*0b.*.*fsd.*\$fd0,\[\$r0\+\(\$r1<<#0x1\)\]
.*.*a8:.*6a.*00.*05.*8b.*.*fsd.bi.*\$fd0,\[\$r0\],\(\$r1<<#0x1\)
.*.*ac:.*36.*00.*00.*01.*.*fsdi.*\$fd0,\[\$r0\+#0x4\]
.*.*b0:.*36.*00.*10.*01.*.*fsdi.bi.*\$fd0,\[\$r0\],#0x4
.*.*b4:.*6a.*00.*83.*c0.*.*fs2d.*\$fd0,\$fs1
.*.*b8:.*6a.*00.*a3.*c8.*.*fui2d.*\$fd0,\$fs1
.*.*bc:.*6a.*00.*b3.*c8.*.*fsi2d.*\$fd0,\$fs1
.*.*c0:.*6a.*00.*c3.*c8.*.*fd2ui.*\$fs0,\$fd1
.*.*c4:.*6a.*00.*e3.*c8.*.*fd2si.*\$fs0,\$fd1
.*.*c8:.*6a.*00.*d3.*c8.*.*fd2ui.z.*\$fs0,\$fd1
.*.*cc:.*6a.*00.*f3.*c8.*.*fd2si.z.*\$fs0,\$fd1
.*.*d0:.*6a.*00.*83.*c8.*.*fd2s.*\$fs0,\$fd1
