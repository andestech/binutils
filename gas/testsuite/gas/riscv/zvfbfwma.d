#as: -march=rv32iv_zvfbfwma
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+eec41257[ 	]+vfwmaccbf16.vv[  	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+ecc41257[ 	]+vfwmaccbf16.vv[  	]+v4,v8,v12,v0.t
[ 	]+[0-9a-f]+:[ 	]+ee855257[ 	]+vfwmaccbf16.vf[  	]+v4,fa0,v8
[ 	]+[0-9a-f]+:[ 	]+ec855257[ 	]+vfwmaccbf16.vf[  	]+v4,fa0,v8,v0.t
