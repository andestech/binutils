foo:
! APG 3.3.1 
	lwi $r1, [$r2]
	lbsi $r1, [$r2]
	swi $r1, [$r2]
	lw $r1, [$r2 + $r3]
	lbs $r1, [$r2 + $r3]
	sw $r1, [$r2 + $r3]
	lw $r1, [$r2]
	lbs $r1, [$r2]
	sw $r1, [$r2]
	lw.p $r1, [$r2], $r3
	lbs.p $r1, [$r2], $r3
	lmw.adm $r1, [$r2], $r3
	smw.adm $r1, [$r2], $r3
	lwup $r1, [$r2 + $r3]
	swup $r1, [$r2 + $r3]
	lwi333 $r1, [$r2]
	swi333 $r1, [$r2]
	lwi37 $r1, [$fp]
	swi37 $r1, [$fp]
	jral $r1
	ret
	ret5
	llw $r1, [$r2 + $r3]
	scw $r1, [$r2 + $r3]
	dprefi.d srd, [$r1]
	dprefi.w srd, [$r1]
	dpref srd, [$r1+$r2]
	dpref srd, [$r1]
	msync
	trap
	teqz $r1
	tnez $r1
	break
	
