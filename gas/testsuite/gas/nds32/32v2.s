foo:
! Table 45. ALU Instructions
	addi.gp $r25,#-184470
! Table 46. Multiply and Divide Instructions	
	mulr64 $r16,$r2,$r7
	mulsr64 $lp,$r11,$r13
	maddr32 $lp,$r17,$r25
	msubr32 $r1,$r0,$r4
	divr $r16,$r0,$r0,$r16
	divsr $r20,$r3,$r6,$r8
! Table 47. Load/Store Instructions
	lbi.gp $r2,[+#-184270]
	lbsi.gp $lp,[+#-57377]	
	lhi.gp $r0,[+#0x0]
	lhsi.gp $r26,[+#-6008]
	lwi.gp $r15,[+#-133172]
	sbi.gp $r15,[+#0x3e013]
	shi.gp $r15,[+#0x3c3f2]
	swi.gp $r25,[+#-148240]
	lmwa.bim $r21,[$r25],$r21,#0x1
	smwa.ai $r6,[$r27],$r11,#0x1
	lbup $r26,[$r8+$r23<<#0x1]
	sbup $r19,[$r20+$r16<<#0x3]
	