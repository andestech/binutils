foo:
	.omit_fp_begin
	la    $fp, _FP_BASE_
  	l.w   $r0, _data_0
  	l.w   $r1, _data_1
  	l.w   $r2, _data_2
  	l.w   $r3, _data_3
  	l.w   $r4, _data_4
	.omit_fp_end
