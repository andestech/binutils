foo:
! Table 33. Move Instruction (16-bit)
	movi55 $r0, -16
	mov55 $r0, $r1
! Table 34. Add/Sub Instruction with Immediate (16-bit)
	addi45 $r0, 0
	addi45 $r11, 31
	addi333 $r0, $r0, 0
	addi333 $r7, $r7, 7
	subi45 $r0, 0
	subi333 $r0, $r0, 0
! Table 35. Add/Sub Instruction (16-bit)
	add45 $r0, $r1
	add333 $r0, $r1, $r2
	sub45 $r0, $r1
	sub333 $r0, $r1, $r2
! Table 36. Shift Instruction with Immediate (16-bit)
	srai45 $r1, 1
	srli45 $r1, 1
	slli333 $r0, $r1, 1
! Table 37. Bit Field Mask Instruction with Immediate (16-bit)
	!bfmi333 $r0, $r1, 1
	zeb33 $r0, $r1
	zeh33 $r0, $r1
	seb33 $r0, $r1
	seh33 $r0, $r1
	xlsb33 $r0, $r1
	x11b33 $r0, $r1
! Table 38. Load / Store Instruction (16-bit)
	lwi450 $r0, [$r1]
	lwi333 $r4,[$r7+#0xc]
	lwi333.bi $r0, [$r1], 0xc
	lhi333 $r0, [$r1+#0xc]
	lbi333 $r0, [$r1+#0x1]
	swi450 $r0, [$r1]
	swi333 $r0, [$r1+#0xc]
	swi333.bi $r0, [$r1], 0xc
	shi333 $r0, [$r1+#0xc]
	sbi333 $r0, [$r1+#0x1]
! Table 39. Load/Store Instruction with Implied FP (16-bit)
	lwi37 $r0, [$fp+#0xc]
	swi37 $r0, [$fp+#0xc]
! Table 40. Branch and Jump Instruction (16-bit)
	beqs38 $r0, 0xc
	bnes38 $r0, 0xc
	beqz38 $r0, 0xc
	bnez38 $r0, 0xc
	j8 0xc
	jr5 $r0
	ret5 $r0
	jral5 $r0
! Table 41. Compare and Branch Instruction (16-bit)
	slti45 $r0, 0xc
	sltsi45 $r0, 0xc
	slt45 $r0, $r11
	slts45 $r0, $r1
	beqzs8 0xc
	bnezs8 0xc
! Table 42. Misc. Instruction (16-bit)
	break16 #0xc
	nop16
	
