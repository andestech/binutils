foo:
	!mmac
	madds64 $d0, $r0, $r1
	!div and dx-regs
	div $d0, $r1, $r2
	!16bit-ext
	movi55 $r0, -16
	!perf-ext
	abs $r1, $r2
	!perf2-ext
	bse $r1, $r2, $r3
	!string-ext
	ffb $r1, $r2, $r3
	!audio-isa-ext
	aaddl $r22,$gp,$r9,$r23,[$i7],$m7
	!fpu-fma-ext, ignored
	fmadds $fs0, $fs1, $fs2
	fmaddd $fd0, $fd1, $fd2
	!fpu-sp-ext
	fadds $fs0, $fs1, $fs2
	!fpu-dp-ext
	faddd $fd0, $fd1, $fd2
	!dsp-ext
	kadd16 $r0,$r1,$r2
	!zol-ext	
	mtlbi 0xfffe
	!no-reduced-regs
	addi $r0, $r11, 5
