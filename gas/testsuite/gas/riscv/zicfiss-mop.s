target:
	# sspush   x1 == mop.rr.7 x0, x0, x1
	# sspush   x5 == mop.rr.7 x0, x0, x5
	mop.rr.7	zero, zero, ra
	mop.rr.7	zero, zero, t0

	# sspopchk x1 == mop.r.28 x0, x1
	# sspopchk x5 == mop.r.28 x0, x5
	mop.r.28	zero, ra
	mop.r.28	zero, t0

	# c.sspush   x1 == c.mop.1
	# c.sspopchk x5 == c.mop.5
	c.mop.1
	c.mop.5

	# ssrdp rd == mop.r.28 rd, x0 (rd != 0)
	mop.r.28	sp, zero
