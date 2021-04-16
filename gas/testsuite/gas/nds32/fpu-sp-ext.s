foo:
	!Table 2. Single-precision arithmetic instructions
	fadds $fs0, $fs1, $fs2
	fsubs $fs0, $fs1, $fs2
	fmuls $fs0, $fs1, $fs2
	fdivs $fs0, $fs1, $fs2
	fsqrts $fs0, $fs1
	fmadds $fs0, $fs1, $fs2
	fmsubs $fs0, $fs1, $fs2
	fnmadds $fs0, $fs1, $fs2
	fnmsubs $fs0, $fs1, $fs2

	!Table 4. Single-precision compare instructions
	fcmpeqs $fs0, $fs1, $fs2
	fcmplts $fs0, $fs1, $fs2
	fcmples $fs0, $fs1, $fs2
	fcmpuns $fs0, $fs1, $fs2
	fcmpeqs.e $fs0, $fs1, $fs2
	fcmplts.e $fs0, $fs1, $fs2
	fcmples.e $fs0, $fs1, $fs2
	fcmpuns.e $fs0, $fs1, $fs2

	!Table 6. Copy/Move instructions common to both single-precision and double-precision
	fmfcfg $r0
	fmfcsr $r0
	fmtcsr $r0
	fmfsr $r0, $fs3
	fmtsr $r0, $fs3

	!Table 7. Single-precision copy/move instructions
	fabss $fs0, $fs1
	fcpyss $fs0, $fs1, $fs2
	fcpynss $fs0, $fs1, $fs2
	fcmovzs $fs0, $fs1, $fs2
	fcmovns $fs0, $fs1, $fs2

	!Table 9. Load/Store instructions common to both Single-precision and Double-precision
	fls $fs0, [$r0 + ($r1<<3)]
	fls.bi $fs0, [$r0], ($r1<<3)
	flsi $fs0, [$r0 + 0xffc]
	flsi.bi $fs0, [$r0], 0xffc
	fss $fs0, [$r0 + ($r1<<1)]
	fss.bi $fs0, [$r0], ($r1<<1)
	fssi $fs0, [$r0 + 0x4]
	fssi.bi $fs0, [$r0], 0x4

	!Table 11. Single-precision data format conversion instructions
	fui2s $fs0, $fs1
	fsi2s $fs0, $fs1
	fs2ui $fs0, $fs1
	fs2si $fs0, $fs1
	fs2ui.z $fs0, $fs1
	fs2si.z $fs0, $fs1
	!fs2d $fd0, $fs1
