.data
	.set lala,. 
	.rept 2048 
	.word 0x1111
	.endr
	.set gaga,. 
	.rept 2048 
	.word 0x2222
	.endr
	.set kiki,. 
	.rept 2048 
	.word 0x1111
	.endr
	.set vivi,. 
	.rept 2048 
	.word 0x2222
	.endr
.text
.globl _start
_start:
	.relax_hint 0
	la      $r0, lala               ! gp - 0x4000
	.relax_hint 0
	fldi    $fd0, [$r0 + 0x2000-4]  ! gp - 0x2000 - 4 (x)

	.relax_hint 1
	la      $r0, gaga               ! gp - 0x2000
	.relax_hint 1
	fldi    $fd0, [$r0 + 0x1000]    ! gp - 0x1000 (v)

	.relax_hint 2
	la      $r0, kiki               ! gp + 0
	.relax_hint 2
	fldi    $fd0, [$r0 - 0x1000]    ! gp - 0x1000 (v)

	.relax_hint 3
	la      $r0, kiki               ! gp + 0
	.relax_hint 3
	fldi    $fd0, [$r0 + 0x2000-4]  ! gp + 0x2000 - 4 (v)

	.relax_hint 4
	la      $r0, vivi               ! gp + 0x2000
	.relax_hint 4
	fldi    $fd0, [$r0 - 4]         ! gp + 0x2000 - 4 (v)

	nop
	nop

	.relax_hint 5
	la      $r0, lala               ! gp - 0x4000
	.relax_hint 5
	fldi    $fd0, [$r0 + 0x2000 -4] ! gp - 0x2000 (CFAIL)

	.relax_hint 6
	la      $r0, gaga               ! gp - 0x2000
	.relax_hint 6
	fldi    $fd0, [$r0 + 0x1000 - 4]! gp - 0x1000 - 4 (x)

	.relax_hint 7
	la      $r0, kiki               ! gp + 0
	.relax_hint 7
	fldi    $fd0, [$r0 - 0x1000 - 4]! gp - 0x1000 - 4 (x)

	.relax_hint 8
	la      $r0, kiki               ! gp + 0
	.relax_hint 8
	fldi    $fd0, [$r0 + 0]         ! gp + 0 (v)

	.relax_hint 9
	la      $r0, vivi               ! gp + 0x2000
	.relax_hint 9
	fldi    $fd0, [$r0]             ! gp + 0x2000 (x)
