#as: -march=rv32g_zcmb
#source: zc-zcmb-lh.s
#objdump: -dr -Mno-aliases

.*:[	 ]+file format .*


Disassembly of section .text:

0+000 <zcmb_lh>:
[	 ]*[0-9a-f]+:[	 ]+3000[	 ]+cm.lh[	 ]+s0,0\(s0\)
.*R_RISCV_RELAX_ENTRY.*
[	 ]*[0-9a-f]+:[	 ]+33bc[	 ]+cm.lh[	 ]+a5,2\(a5\)
[	 ]*[0-9a-f]+:[	 ]+3340[	 ]+cm.lh[	 ]+s0,4\(a4\)
[	 ]*[0-9a-f]+:[	 ]+3a9c[	 ]+cm.lh[	 ]+a5,16\(a3\)
[	 ]*[0-9a-f]+:[	 ]+3e04[	 ]+cm.lh[	 ]+s1,24\(a2\)
[	 ]*[0-9a-f]+:[	 ]+3fe0[	 ]+cm.lh[	 ]+s0,30\(a5\)
[	 ]*[0-9a-f]+:[	 ]+3730[	 ]+cm.lh[	 ]+a2,10\(a4\)
[	 ]*[0-9a-f]+:[	 ]+3304[	 ]+cm.lh[	 ]+s1,0\(a4\)
[	 ]*[0-9a-f]+:[	 ]+33ac[	 ]+cm.lh[	 ]+a1,2\(a5\)
[	 ]*[0-9a-f]+:[	 ]+3040[	 ]+cm.lh[	 ]+s0,4\(s0\)
[	 ]*[0-9a-f]+:[	 ]+3884[	 ]+cm.lh[	 ]+s1,16\(s1\)
[	 ]*[0-9a-f]+:[	 ]+3e00[	 ]+cm.lh[	 ]+s0,24\(a2\)
[	 ]*[0-9a-f]+:[	 ]+3ff4[	 ]+cm.lh[	 ]+a3,30\(a5\)
[	 ]*[0-9a-f]+:[	 ]+3738[	 ]+cm.lh[	 ]+a4,10\(a4\)
[	 ]*[0-9a-f]+:[	 ]+300c[	 ]+cm.lh[	 ]+a1,0\(s0\)
[	 ]*[0-9a-f]+:[	 ]+3384[	 ]+cm.lh[	 ]+s1,0\(a5\)
