foo:
! Table 11, load store immediate, baseline
	lwi $r0, [$r1 + (1 << 2)]
	lhi $r0, [$r1 + (1 << 1)]
	lhsi $r0, [$r1 + (-1 << 1)]
	lbi $r0, [$r1 + 1]
	lbsi $r0, [$r1 + (-1)]
	swi $r0, [$r1 + (1 << 2)]
	shi $r0, [$r1 + (1 << 1)]
	sbi $r0, [$r1 + 1]
! Table 12, load store instruction, baseline
	lwi.bi $r0, [$r1], (1 << 2)
	lhi.bi $r0, [$r1], (1 << 1)
	lhsi.bi $r0, [$r1], (-1 << 1)
	lbi.bi $r0, [$r1], 1
	lbsi.bi $r0, [$r1], -1
	swi.bi $r0, [$r1], (1 << 2)
	shi.bi $r0, [$r1], (1 << 1)
	sbi.bi $r0, [$r1], 1
! Table 13, load store	instruction, baseline
	lw $r0, [$r1 + ($r2 << 1)]
	lh $r0, [$r1 + ($r2 << 1)]
	lhs $r0, [$r1 + ($r2 << 1)]
	lb $r0, [$r1 + ($r2 << 1)]
	lbs $r0, [$r1 + ($r2 << 1)]
	sw $r0, [$r1 + ($r2 << 1)]
	sh $r0, [$r1 + ($r2 << 1)]
	sb $r0, [$r1 + ($r2 << 1)]
! Table 14, load store	instruction, baseline	
	lw.bi $r0, [$r1], $r2 << 1
	lh.bi $r0, [$r1], $r2 << 1
	lhs.bi $r0, [$r1], $r2 << 1
	lb.bi $r0, [$r1], $r2 << 1
	lbs.bi $r0, [$r1], $r2 << 1
	sw.bi $r0, [$r1], $r2 << 1
	sh.bi $r0, [$r1], $r2 << 1
	sb.bi $r0, [$r1], $r2 << 1
! Table 15, load store multiple word, baseline
	lmw.bim $r0,[$r4],$r3,#0x2
	lmw.aim $r0,[$r4],$r3,#0x2
	lmw.bdm $r0,[$r4],$r3,#0x2
	lmw.adm $r0,[$r4],$r3,#0x2
	lmw.bd $r0,[$r4],$r3,#0x2
	smw.bim $r0,[$r4],$r3,#0x2
	smw.aim $r0,[$r4],$r3,#0x2
	smw.bdm $r0,[$r4],$r3,#0x2
	smw.adm $r0,[$r4],$r3,#0x2
	smw.bd $r0,[$r4],$r3,#0x2
! Table 16,  load store instruction for atomic update, baseline
	llw $r0,[$r3+($r5<<#0x3)]
	scw $r0,[$r3+$r5<<#0x2]
! Table 17,  load store instruction with user-mode priviledge 
	lwup $r6,[$r0+($r19<<#0x3)]
	swup $r15,[$r21+$r26<<#0x2]
