foo:
! Table 21, Read/Write System Registers, baseline
	mfsr $r18, $core_id
	mtsr $fp, $bpam4
! Table 22, Jump Register with System Register Update (Baseline)
	jr.itoff $r1
	jr.toff $r1
	jral.iton $r1
	jral.iton $r1, $r2
	jral.ton $r1
	jral.ton $r1, $r2
! Table 23. MMU Instruction (Baseline)	
	tlbop $r6, rwlk
	