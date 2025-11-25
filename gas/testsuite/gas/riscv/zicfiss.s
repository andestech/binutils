target:
	# Auto-compressed variants
	sspush		ra
	c.sspush	ra
	sspopchk	t0
	c.sspopchk	t0

	# All uncompressed forms
	sspush		t0
	sspopchk	ra
	ssrdp		a0
	ssamoswap.w	a0, a0, 0(a0)
	ssamoswap.w	a0, a0, (a0)
