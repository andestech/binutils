	.data
	.size	var, 4
  .flag verbatim
var:
	.word 10
	.text
foo:
! 1. load 32-bit value/address
	li $r1, 0x1 ! load immediate
	li $r1, 0xFF ! load immediate
	li $r1, 0x80000 ! load immediate
	li $r1, 0x80001 ! load immediate
	la $r1, var ! load address
! 2. load/store variables	
	l.b $r1, var  ! load value of variable 
	l.b $r1, $r2  ! load value of variable 
	l.h $r1, var  ! load value of variable 
	l.h $r1, $r2  ! load value of variable 
	l.w $r1, var  ! load value of variable 
	l.w $r1, $r2  ! load value of variable 
	l.bs $r1, var ! 
	l.bp $r1, var, 1 ! load value of variable, and 
	l.hp $r1, var, 2 ! load value of variable, and 
	l.wp $r1, var, 4 ! load value of variable, and 
	l.bpc $r1, 1
	l.hpc $r1, 2
	l.wpc $r1, 4
	!1.bsp $r1, var, 1  ! FIXME: incorrect syntax, see docs
	!l.bspc $r1, var, 1  ! FIXME: incorrect syntax
	s.b $r1, var
	s.bp $r1, var, 1
	!s.bpc $r1, var, 1  ! FIXME: incorrect syntax
! 3. negation	
	not $r1, $r2
	neg $r1, $r2
! 4. branch to label	
	br $r1
	b foo
	beq $r1, $r2, foo
	bne $r1, $r2, foo
	bge $r1, $r2, foo
	bges $r1, $r2, foo
	bgt $r1, $r2, foo
	bgts $r1, $r2, foo
	blt $r1, $r2, foo
	blts $r1, $r2, foo
	ble $r1, $r2, foo
	bles $r1, $r2, foo
! 5. branch and link to function name
	bral $r1
	bal foo
	call foo
	bgezal $r1, foo
	bltzal $r1, foo
! 6. move
  move $r1, $r2
  move $r1, foo
  move $r1, 1
! 7. push/pop
  pushm $r28, $r29
	push $r1
	push.d var
	push.w var
	push.h var
	push.b var
	push.b var, $r1
	pusha var
	pusha var, $r1
	pushi 1
	pushi 1, $r1
	popm $r1, $r2
	pop $r1
	pop.d var, $r1
	pop.w var, $r1
	pop.h var, $r1
	pop.b var, $r1
	pop.b var, $r1, $r2

  lbi.p $r1, [$r2], 1
  lhi.p $r1, [$r2], 2
  lwi.p $r1, [$r2], 4
  sbi.p $r1, [$r2], 1
  shi.p $r1, [$r2], 2
  swi.p $r1, [$r2], 4
  lbsi.p $r1, [$r2], 1
  lhsi.p $r1, [$r2], 2
  lwsi.p $r1, [$r2], 4
  v3push $r6, 0
  v3pop $r6, 0
.16bit_off
  move $r1, $r2
  push.s $r1,$r6, { $fp $gp $lp $sp }
  push.s { $fp $gp $lp $sp }
  pop.s $r1,$r6, { $fp $gp $lp $sp }
