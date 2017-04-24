foo:
	beq $r0, $r1, lo20(foo)
	beq $r0, $r1, hi20(100)
	beq $r0, $r1, lo12(100)
	beq $r0, $r1, lo20(100)
	bne $r0, $r1, foo
