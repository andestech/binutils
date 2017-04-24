foo:
! Table 48. Baseline V3 and V3m Instructions
	add_slli $r25,$r20,$r5,#0x11
	add_srli $lp,$fp,$r2,#0x0
	and_slli $r0,$r6,$r0,#0x9
	and_srli $r12,$r7,$r10,#0x8
	bitc $r15,$r18,$r17
	bitci $r23,$r22,#0x2bcf
	beqc $r0,#0x1b6,4
	bnec $r10,#-277,4
	cctl $gp,l1i_ix_inval
	jralnez $r26,$r26
	jrnez $r6
	or_slli $sp,$r8,$r9,#0x3
	or_srli $r11,$r26,$gp,#0x1a
	sub_slli $r16,$r5,$r25,#0x10
	sub_srli $r26,$r6,$r15,#0xd
	xor_slli $r19,$r24,$r26,#0x3
	xor_srli $r12,$r7,$sp,#0x3
	
	
	