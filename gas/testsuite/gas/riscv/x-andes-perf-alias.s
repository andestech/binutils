target:
	bbc a0, 0, target
	bbs a0, 0, target
	beqc a0, 0, target
	bnec a0, 0, target
	bfos a0, a1, 0, 0
	bfoz a0, a1, 0, 0
	lea.h a0, a1, a2
	lea.w a0, a1, a2
	lea.d a0, a1, a2
	lea.b.ze a0, a1, a2
	lea.h.ze a0, a1, a2
	lea.w.ze a0, a1, a2
	lea.d.ze a0, a1, a2
	addigp a0, target
	lbgp a0, target
	lbugp a0, target
	lhgp a0, target
	lhugp a0, target
	lwgp a0, target
	lwugp a0, target
	ldgp a0, target
	sbgp a0, target
	shgp a0, target
	swgp a0, target
	sdgp a0, target
	ffb a0, a1, a2
	ffzmism a0, a1, a2
	ffmism a0, a1, a2
	flmism a0, a1, a2
