foo:
  aaddl $r22,$gp,$r9,$r23,[$i7],$m7
  asubl $r8,$r25,$sp,$r9,[$i4],$m5
  amtari $m7,#0x53fc
  
  amadd $d0,$r0,$r0
  amabbs $d1,$r2,$r22
  alr $lp,[$i3],$m3
  alr2 $lp,$r11,[$i3],[$i7],$m3,$m5
  amaddl.s $d0,$r0,$r13,[$i7],$m7
  amaddl.l $d0,$r12,$r7,$r3,[$i5],$m5
  amaddl2.s $d1,$r9,$r14,[$i2],[$i6],$m0,$m4
  amaddl2.l $d1,$r15,$r14,$r12,$r13,[$i1],[$i5],$m0,$m5
  amaddsa $d1,$r11,$r14,$d0.lo,[$i5],$m4
  
  amsub $d0,$r4,$r0
  amabts $d0,$r0,$r0
  asr $r0,[$i4],$m7
  amsubl.s $d0,$r3,$r14,[$i4],$m7
  amsubl.l $d0,$r12,$r7,$r3,[$i5],$m5
  amsubl2.s $d1,$fp,$r11,[$i0],[$i4],$m1,$m4
  amsubl2.l $d1,$r14,$r14,$r10,$r11,[$i1],[$i5],$m2,$m5
  amsubsa $d0,$r10,$r3,$d0.lo,[$i0],$m0
  
  amult $d0,$r4,$r0
  amatbs $d0,$r21,$fp
  ala $d0.hi,[$i7],$m7
  asats48 $d0
  awext $r4,$d0,#0x7
  amultl.s $d0,$r10,$r19,[$i3],$m1
  amultl.l $d0,$r6,$r11,$r8,[$i5],$m7
  amultl2.s $d0,$r21,$r17,[$i2],[$i6],$m3,$m4
  amultl2.l $d0,$r6,$r3,$r6,$r7,[$i2],[$i6],$m1,$m4
  amultsa $d1,$r5,$lp,$d1.lo,[$i3],$m1
  
  amatts $d0,$r4,$r0
  asa $d0.hi,[$i7],$m7
  amtar $r0,$i5
  amfar $r0,$i5
  amtar2 $r0,$i5
  amfar2 $r0,$i5
  
  amadds $d0,$r4,$r0
  ambbs $d0,$r4,$r0
  amawbs $d0,$r4,$r0
  aupi $i7,$m7
  amaddsl.s $d1,$r22,$r9,[$i4],$m6
  amaddsl.l $d0,$r4,$r0,$r0,[$i1],$m2
  amaddsl2.s $d1,$r15,$r20,[$i0],[$i4],$m3,$m5
  amaddsl2.l $d0,$r10,$r14,$r14,$r15,[$i0],[$i4],$m3,$m6
  amaddssa $d0,$lp,$r24,$d0.lo,[$i7],$m7
  
  amsubs $d0,$r4,$r0
  ambts $d0,$r4,$r0
  amawts $d0,$r4,$r0
  amsubsl.s $d1,$r6,$r7,[$i4],$m6
  amsubsl.l $d1,$r9,$r10,$r15,[$i1],$m1
  amsubsl2.s $d0,$r4,$r1,[$i0],[$i4],$m0,$m4
  amsubsl2.l $d1,$r7,$r9,$r14,$r15,[$i0],[$i4],$m3,$m4
  amsubssa $d0,$r9,$r7,$d1.lo,[$i3],$m3
  
  amults $d0,$r4,$r0
  amtbs $d0,$r4,$r0
  amwbs $d0,$r4,$r0
  amultsl.s $d0,$r13,$r5,[$i7],$m7
  amultsl.l $d1,$r4,$r9,$r14,[$i4],$m7
  amultsl2.s $d0,$r20,$r20,[$i0],[$i4],$m0,$m4
  amultsl2.l $d1,$r7,$r11,$r10,$r11,[$i3],[$i7],$m3,$m4
  amultssa $d0,$r5,$r4,$d0.lo,[$i1],$m0
  
  amnegs $d0,$r4,$r0
  amtts $d0,$r4,$r0
  amwts $d0,$r4,$r0
  amnegsl.s $d1,$r4,$sp,[$i1],$m0
  amnegsl.l $d0,$r14,$r5,$r7,[$i0],$m1
  amnegsl2.s $d1,$r2,$fp,[$i2],[$i6],$m1,$m5
  amnegsl2.l $d0,$r7,$r10,$r10,$r11,[$i0],[$i4],$m0,$m6
  amnegssa $d0,$r14,$r7,$d0.hi,[$i4],$m5
  
  
  amtari $m7,#0x53fc
  
  amawbsl.s $d1,$r21,$sp,[$i4],$m5
  amawbsl.l $d0,$r4,$r0,$r1,[$i7],$m7
  amawbsl2.s $d1,$r20,$r16,[$i2],[$i6],$m1,$m7
  amawbsl2.l $d1,$r0,$r2,$r0,$r1,[$i0],[$i4],$m1,$m4
  amawbssa $d1,$r12,$r14,$d1.hi,[$i0],$m1
  
  amawtsl.s $d1,$r21,$sp,[$i4],$m5
  amawtsl.l $d1,$r5,$r5,$r1,[$i0],$m3
  amawtsl2.s $d0,$r12,$r5,[$i1],[$i5],$m3,$m7
  amawtsl2.l $d1,$r0,$r2,$r0,$r1,[$i0],[$i4],$m1,$m4
  amawtssa $d0,$r8,$p1,$d0.hi,[$i0],$m1
  
  amwbsl.s $d1,$r22,$r10,[$i6],$m6
  amwbsl.l $d1,$r7,$r15,$r8,[$i1],$m3
  amwbsl2.s $d1,$r7,$r21,[$i1],[$i5],$m1,$m7
  amwbsl2.l $d0,$r3,$r2,$r2,$r3,[$i3],[$i7],$m1,$m4
  amwbssa $d1,$r10,$r18,$d0.hi,[$i2],$m3
  
  amwtsl.s $d0,$lp,$r0,[$i7],$m7
  amwtsl.l $d0,$r2,$r4,$r4,[$i3],$m1
  amwtsl2.s $d0,$r2,$r5,[$i0],[$i4],$m1,$m4
  amwtsl2.l $d1,$r7,$r3,$r0,$r1,[$i0],[$i4],$m3,$m6
  amwtssa $d1,$p0,$r10,$d1.lo,[$i6],$m4
  
  amabbsl.s $d0,$r3,$r5,[$i5],$m4
  amabbsl.l $d0,$r2,$r4,$r4,[$i3],$m1
  amabbsl2.s $d0,$r17,$r23,[$i0],[$i4],$m3,$m5
  amabbsl2.l $d0,$r8,$r12,$r14,$r15,[$i1],[$i5],$m1,$m5
  amabbssa $d1,$r2,$r8,$d1.hi,[$i3],$m0
  
  amabtsl.s $d0,$r3,$r5,[$i5],$m4
  amabtsl.l $d0,$r2,$r4,$r4,[$i3],$m1
  amabtsl2.s $d1,$r4,$r0,[$i0],[$i4],$m0,$m4
  amabtsl2.l $d1,$r10,$r13,$r12,$r13,[$i2],[$i6],$m3,$m5
  amabtssa $d0,$r19,$r16,$d1.lo,[$i3],$m3
  
  amatbsl.s $d0,$r3,$r5,[$i5],$m4
  amatbsl.l $d0,$r12,$r3,$r1,[$i6],$m4
  amatbsl2.s $d1,$r17,$r4,[$i0],[$i4],$m3,$m4
  amatbsl2.l $d0,$r4,$r7,$r4,$r5,[$i0],[$i4],$m3,$m7
  amatbssa $d0,$r17,$r4,$d1.lo,[$i0],$m2
  
  amattsl.s $d1,$r13,$lp,[$i4],$m7
  amattsl.l $d0,$r12,$r3,$r1,[$i6],$m4
  amattsl2.s $d1,$r12,$r17,[$i3],[$i7],$m1,$m4
  amattsl2.l $d0,$r4,$r7,$r4,$r5,[$i0],[$i4],$m3,$m7
  amattssa $d0,$r17,$r4,$d1.lo,[$i0],$m2
  
  ambbsl.s $d1,$r23,$r24,[$i5],$m5
  ambbsl.l $d0,$r12,$r3,$r1,[$i6],$m4
  ambbsl2.s $d0,$r15,$r5,[$i2],[$i6],$m0,$m5
  ambbsl2.l $d1,$r9,$r1,$r4,$r5,[$i3],[$i7],$m2,$m4
  ambbssa $d0,$r18,$r25,$d0.lo,[$i5],$m5
  
  ambtsl.s $d1,$p1,$r1,[$i7],$m6
  ambtsl.l $d0,$r0,$r14,$r15,[$i7],$m4
  ambtsl2.s $d0,$r5,$r12,[$i0],[$i4],$m1,$m7
  ambtsl2.l $d1,$r9,$r1,$r4,$r5,[$i3],[$i7],$m2,$m4
  ambtssa $d0,$r18,$r6,$d1.hi,[$i1],$m0
  
  amtbsl.s $d1,$r8,$r23,[$i3],$m1
  amtbsl.l $d1,$r12,$r8,$r14,[$i0],$m0
  amtbsl2.s $d1,$r6,$p0,[$i1],[$i5],$m3,$m6
  amtbsl2.l $d1,$r3,$r6,$r4,$r5,[$i1],[$i5],$m0,$m6
  amtbssa $d1,$r22,$r4,$d1.lo,[$i2],$m2
  
  amttsl.s $d1,$r22,$r9,[$i5],$m6
  amttsl.l $d0,$r1,$r10,$r12,[$i3],$m3
  amttsl2.s $d1,$r6,$p0,[$i1],[$i5],$m3,$m6
  amttsl2.l $d1,$r3,$r6,$r4,$r5,[$i1],[$i5],$m0,$m6
  amttssa $d1,$r22,$r4,$d1.lo,[$i2],$m2
