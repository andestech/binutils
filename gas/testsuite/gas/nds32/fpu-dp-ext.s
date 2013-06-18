foo:
	!Table 3. Double-precision arithmetic instructions
	faddd $fd0, $fd1, $fd2
	fsubd $fd0, $fd1, $fd2
	fmuld $fd0, $fd1, $fd2
	fdivd $fd0, $fd1, $fd2
	fsqrtd $fd0, $fd1
	fmaddd $fd0, $fd1, $fd2
	fmsubd $fd0, $fd1, $fd2
	fnmaddd $fd0, $fd1, $fd2
	fnmsubd $fd0, $fd1, $fd2
	
	!Table 5. Double-precision compare instructions
	fcmpeqd $fs0, $fd1, $fd2
	fcmpltd $fs0, $fd1, $fd2
	fcmpled $fs0, $fd1, $fd2
	fcmpund $fs0, $fd1, $fd2
	fcmpeqd.e $fs0, $fd1, $fd2
	fcmpltd.e $fs0, $fd1, $fd2
	fcmpled.e $fs0, $fd1, $fd2
	fcmpund.e $fs0, $fd1, $fd2

	!Table 6. Copy/Move instructions common to both single-precision and double-precision
	fmfcfg $r0
	fmfcsr $r0
	fmtcsr $r0
	fmfsr $r0, $fs3
	fmtsr $r0, $fs3

	!Table 8. Double-precision copy/move instructions
	fabsd $fd0, $fd1
	fcpysd $fd0, $fd1, $fd2
	fcpynsd $fd0, $fd1, $fd2
	fcmovzd $fd0, $fd1, $fs2
	fcmovnd $fd0, $fd1, $fs2
	fmfdr $r0, $fd1
	fmtdr $r0, $fd1

	!Table 9. Load/Store instructions common to both Single-precision and Double-precision
	fls $fs0, [$r0 + ($r1<<3)]
	fls.bi $fs0, [$r0], ($r1<<3)
	flsi $fs0, [$r0 + 0xffc]
	flsi.bi $fs0, [$r0], 0xffc
	fss $fs0, [$r0 + ($r1<<1)]
	fss.bi $fs0, [$r0], ($r1<<1)
	fssi $fs0, [$r0 + 0x4]
	fssi.bi $fs0, [$r0], 0x4

	!Table 10. Double-precision load/store instructions
	fld $fd0, [$r0 + ($r1<<3)]
        fld.bi $fd0, [$r0], ($r1<<3)
        fldi $fd0, [$r0 + 0xffc]
        fldi.bi $fd0, [$r0], 0xffc
        fsd $fd0, [$r0 + ($r1<<1)]
        fsd.bi $fd0, [$r0], ($r1<<1)
        fsdi $fd0, [$r0 + 0x4]
        fsdi.bi $fd0, [$r0], 0x4

	!Table 12. Double-precision data format conversion instructions
	!Table 11...
	fs2d $fd0, $fs1
	fui2d $fd0, $fs1
	fsi2d $fd0, $fs1
	fd2ui $fs0, $fd1
	fd2si $fs0, $fd1
	fd2ui.z $fs0, $fd1
	fd2si.z $fs0, $fd1
	fd2s	$fs0, $fd1
