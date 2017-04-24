foo:
	j foo
	jal foo
	jr $r0
	ret $r0
	jral $r0
	jral $r0, $r1
	beq $r0, $r1, foo
	bne $r0, $r1, foo
	beqz $r0, foo
	bnez $r0, foo
	bgez $r0, foo
	bltz $r0, foo
	bgtz $r0, foo
	blez $r0, foo
	bgezal $r0, foo
	bltzal $r0, foo
	