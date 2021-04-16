foo:
! Table 24. Conditional Move (Baseline)
	cmovz $gp,$r25,$r17
	cmovn $r18,$r26,$r13
! Table 25. Synchronization Instruction (Baseline)
	 msync
	 isync $r12
! Table 26. Prefetch Instruction (Baseline)	 
	 dprefi.w swr,[$r21+#0x2ea8]
! Table 27. NOP Instruction (Baseline)
	nop
! Table 28. Serialization Instruction (Baseline)
	dsb
	isb
! Table 29. Exception Generation Instruction (Baseline)	
	break
	syscall #0x241
	trap
	teqz $r7,#0x10e5
	tnez $r21,#0x647e
! Table 30. Special Return Instruction (Baseline)	
	iret
	ret.itoff $r1
	ret.toff $r1
! Table 31. Cache Control Instruction (Baseline)
	cctl $r8,l1d_ix_inval
! Table 32. Miscellaneous Instructions (Baseline)	
	setend.b
	setend.l
	setgie.e
	setgie.d
	standby no_wake_grant
	