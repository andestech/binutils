foo:	
  nop !0
	nop !4
	.byte 0x11 !8
	.2byte 0x2222 !9 a
	nop !b c d e 
	.byte 0x11 !f
	.byte 0x11 !10 11 12 13  + 00 + nop16
	.word 0x22222222 !14 15 16 17
	nop !18 19 1a 1b
	.byte 0x11 !1c
	.align 1
	.2byte 0x2222 !1e 1f
	nop !20 21 22 23
	.byte 0x11 !24
	.align 0x2
	.byte 0x11 !28
	nop
