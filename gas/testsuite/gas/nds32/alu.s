foo:
! Table 5, ALU immediate, baseline v1
	addi $r0, $r1, 2
	subri $r0, $r1, 2
	andi $r0, $r1, 2
	ori $r0, $r1, 2
	xori $r0, $r1, 2
	slti $r0, $r1, 2
	sltsi $r0, $r1, 2
	movi $r0, 2
	sethi $r0, 2
! Table 6, ALU, baseline v1
	add $r0, $r1, $r2
	sub $r0, $r1, $r2
	and $r0, $r1, $r2
	nor $r0, $r1, $r2
	or $r0, $r1, $r2
	xor $r0, $r1, $r2
	slt $r0, $r1, $r2
	slts $r0, $r1, $r2
	sva $r0, $r1, $r2
	svs $r0, $r1, $r2
	zeb $r0, $r1
	zeh $r0, $r1
	wsbh $r0, $r1	
! Table 7, shift instruction, baseline v1
	slli $r0, $r1, 1
	srli $r0, $r1, 1
	srai $r0, $r1, 1
	rotri $r0, $r1, 1
	sll $r0, $r1, $r2
	srl $r0, $r1, $r2
	sra $r0, $r1, $r2
	rotr $r0, $r1, $r2	
! Table 8, multiply instruction, baseline v1
	mul $r0, $r1, $r2
	mults64 $d0, $r1, $r2
	mult64 $d0, $r1, $r2
	madds64 $d0, $r0, $r1
	madd64 $d0, $r0, $r1
	msubs64 $d0, $r0, $r1
	msub64 $d0, $r0, $r1
	mult32 $d0, $r1, $r2
	madd32 $d0, $r1, $r2
	msub32 $d0, $r1, $r2
	mfusr $r0, $pc
	mtusr $r0, $pc	
! Table 9, divide instruction, baseline v1
    div $d0, $r2, $r3
    divs $d0, $r2, $r3
	