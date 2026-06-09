target:
	nds.bbc a0, 0, target
	nds.bbs a0, 0, target
	nds.beqc a0, 0, target
	nds.bnec a0, 0, target
	nds.bfos a0, a1, 0, 0
	nds.bfoz a0, a1, 0, 0
	nds.lea.h a0, a1, a2
	nds.lea.w a0, a1, a2
	nds.lea.d a0, a1, a2
	nds.lea.b.ze a0, a1, a2
	nds.lea.h.ze a0, a1, a2
	nds.lea.w.ze a0, a1, a2
	nds.lea.d.ze a0, a1, a2
	nds.addigp a0, target
	nds.lbgp a0, target
	nds.lbugp a0, target
	nds.lhgp a0, target
	nds.lhugp a0, target
	nds.lwgp a0, target
	nds.lwugp a0, target
	nds.ldgp a0, target
	nds.sbgp a0, target
	nds.shgp a0, target
	nds.swgp a0, target
	nds.sdgp a0, target
	nds.ffb a0, a1, a2
	nds.ffzmism a0, a1, a2
	nds.ffmism a0, a1, a2
	nds.flmism a0, a1, a2
