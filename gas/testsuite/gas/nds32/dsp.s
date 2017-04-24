foo:
	add16 $r0,$r1,$r2
	radd16 $r0,$r1,$r2
	uradd16 $r0,$r1,$r2
	kadd16 $r0,$r1,$r2
	ukadd16 $r0,$r1,$r2
	sub16 $r0,$r1,$r2
	rsub16 $r0,$r1,$r2
	ursub16 $r0,$r1,$r2
	ksub16 $r0,$r1,$r2
	uksub16 $r0,$r1,$r2
	cras16 $r0,$r1,$r2
	rcras16 $r0,$r1,$r2
	urcras16 $r0,$r1,$r2
	kcras16 $r0,$r1,$r2
	ukcras16 $r0,$r1,$r2
	crsa16 $r0,$r1,$r2
	rcrsa16 $r0,$r1,$r2
	urcrsa16 $r0,$r1,$r2
	kcrsa16 $r0,$r1,$r2
	ukcrsa16 $r0,$r1,$r2
	add8 $r0,$r1,$r2
	radd8 $r0,$r1,$r2
	uradd8 $r0,$r1,$r2
	kadd8 $r0,$r1,$r2
	ukadd8 $r0,$r1,$r2
	sub8 $r0,$r1,$r2
	rsub8 $r0,$r1,$r2
	ursub8 $r0,$r1,$r2
	ksub8 $r0,$r1,$r2
	uksub8 $r0,$r1,$r2
	sra16 $r0,$r1,$r2
	srai16 $r0,$r1, 4
	sra16.u $r0,$r1,$r2
	srai16.u $r0,$r1, 4
	srl16 $r0,$r1,$r2
	srli16 $r0,$r1, 4
	srl16.u $r0,$r1,$r2
	srli16.u $r0,$r1, 4
	sll16 $r0,$r1,$r2
	slli16 $r0,$r1, 4
	ksll16 $r0,$r1,$r2
	kslli16 $r0,$r1, 4
	kslra16 $r0,$r1,$r2
	kslra16.u $r0,$r1,$r2
	cmpeq16 $r0,$r1,$r2
	scmplt16 $r0,$r1,$r2
	scmple16 $r0,$r1,$r2
	ucmplt16 $r0,$r1,$r2
	ucmple16 $r0,$r1,$r2
	cmpeq8 $r0,$r1,$r2
	scmplt8 $r0,$r1,$r2
	scmple8 $r0,$r1,$r2
	ucmplt8 $r0,$r1,$r2
	ucmple8 $r0,$r1,$r2
	smin16 $r0,$r1,$r2
	umin16 $r0,$r1,$r2
	smax16 $r0,$r1,$r2
	umax16 $r0,$r1,$r2
	sclip16 $r0,$r1, 4
	uclip16 $r0,$r1, 4
	khm16 $r0,$r1,$r2
	khmx16 $r0,$r1,$r2
	kabs16 $r0,$r1
	smin8 $r0,$r1,$r2
	umin8 $r0,$r1,$r2
	smax8 $r0,$r1,$r2
	umax8 $r0,$r1,$r2
	kabs8 $r0,$r1
	sunpkd810 $r0,$r1
	sunpkd820 $r0,$r1
	sunpkd830 $r0,$r1
	sunpkd831 $r0,$r1
	zunpkd810 $r0,$r1
	zunpkd820 $r0,$r1
	zunpkd830 $r0,$r1
	zunpkd831 $r0,$r1
	raddw $r0,$r1,$r2
	uraddw $r0,$r1,$r2
	rsubw $r0,$r1,$r2
	ursubw $r0,$r1,$r2
	sra.u $r0,$r1,$r2
	srai.u $r0,$r1, 5
	ksll $r0,$r1,$r2
	kslli $r0,$r1, 5
	kslraw.u $r0,$r1,$r2
	pkbb16 $r0,$r1,$r2
	pkbt16 $r0,$r1,$r2
	pktb16 $r0,$r1,$r2
	pktt16 $r0,$r1,$r2
	smmul $r0,$r1,$r2
	smmul.u $r0,$r1,$r2
	kmmac $r0,$r1,$r2
	kmmac.u $r0,$r1,$r2
	kmmsb $r0,$r1,$r2
	kmmsb.u $r0,$r1,$r2
	kwmmul $r0,$r1,$r2
	kwmmul.u $r0,$r1,$r2
	smmwb $r0,$r1,$r2
	smmwb.u $r0,$r1,$r2
	smmwt $r0,$r1,$r2
	smmwt.u $r0,$r1,$r2
	kmmawb $r0,$r1,$r2
	kmmawb.u $r0,$r1,$r2
	kmmawt $r0,$r1,$r2
	kmmawt.u $r0,$r1,$r2
	smbb $r0,$r1,$r2
	smbt $r0,$r1,$r2
	smtt $r0,$r1,$r2
	kmda $r0,$r1,$r2
	kmxda $r0,$r1,$r2
	smds $r0,$r1,$r2
	smdrs $r0,$r1,$r2
	smxds $r0,$r1,$r2
	kmabb $r0,$r1,$r2
	kmabt $r0,$r1,$r2
	kmatt $r0,$r1,$r2
	kmada $r0,$r1,$r2
	kmaxda $r0,$r1,$r2
	kmads $r0,$r1,$r2
	kmadrs $r0,$r1,$r2
	kmaxds $r0,$r1,$r2
	kmsda $r0,$r1,$r2
	kmsxda $r0,$r1,$r2
	smal $r0,$r1,$r2
	sclip32 $r0,$r1, 5
	uclip32 $r0,$r1, 5
	bitrev $r0,$r1,$r2
	bitrevi $r0,$r1, 5
	wext $r0,$r1,$r2
	wexti $r0,$r2, 5
	bpick $r0,$r1,$r2,$r3
	insb $r0,$r1, 2
	add64 $r0,$r1,$r2
	radd64 $r0,$r1,$r2
	uradd64 $r0,$r1,$r2
	kadd64 $r0,$r1,$r2
	ukadd64 $r0,$r1,$r2
	sub64 $r0,$r1,$r2
	rsub64 $r0,$r1,$r2
	ursub64 $r0,$r1,$r2
	ksub64 $r0,$r1,$r2
	uksub64 $r0,$r1,$r2
	smar64 $r0,$r1,$r2
	smsr64 $r0,$r1,$r2
	umar64 $r0,$r1,$r2
	umsr64 $r0,$r1,$r2
	kmar64 $r0,$r1,$r2
	kmsr64 $r0,$r1,$r2
	ukmar64 $r0,$r1,$r2
	ukmsr64 $r0,$r1,$r2
	smalbb $r0,$r1,$r2
	smalbt $r0,$r1,$r2
	smaltt $r0,$r1,$r2
	smalda $r0,$r1,$r2
	smalxda $r0,$r1,$r2
	smalds $r0,$r1,$r2
	smaldrs $r0,$r1,$r2
	smalxds $r0,$r1,$r2
	smslda $r0,$r1,$r2
	smslxda $r0,$r1,$r2
	kaddw $r0,$r1,$r2
	ksubw  $r0,$r1,$r2
	kslraw $r0,$r1,$r2
	kaddh $r0,$r1,$r2
	ksubh  $r0,$r1,$r2
	rdov $r0
	clrov
