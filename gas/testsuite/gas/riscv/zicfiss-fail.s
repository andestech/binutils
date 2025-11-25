target:
	# sspush / sspopchk: only x1 or x5 are allowed.
	sspush		x0
	sspush		x2
	sspush		x31
	sspopchk	x0
	sspopchk	x2
	sspopchk	x31

	# c.sspush x1 / c.sspopchk x5: all other GPRs are not allowed.
	c.sspush	x5
	c.sspopchk	x1
	c.sspush	x0
	c.sspush	x2
	c.sspush	x31
	c.sspopchk	x0
	c.sspopchk	x2
	c.sspopchk	x31

	# ssrdp: rd must not be x0.
	ssrdp		x0
