#as: -march=rv32i_zvfofp8min
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+4a8c9257[ 	]+vfncvtbf16.f.f.q[  	]+v4,v8
[ 	]+[0-9a-f]+:[ 	]+488c9257[ 	]+vfncvtbf16.f.f.q[  	]+v4,v8,v0.t
[ 	]+[0-9a-f]+:[ 	]+4a8d9257[ 	]+vfncvtbf16.sat.f.f.q[  	]+v4,v8
[ 	]+[0-9a-f]+:[ 	]+488d9257[ 	]+vfncvtbf16.sat.f.f.q[  	]+v4,v8,v0.t
[ 	]+[0-9a-f]+:[ 	]+4a8f9257[ 	]+vfncvtbf16.sat.f.f.w[  	]+v4,v8
[ 	]+[0-9a-f]+:[ 	]+488f9257[ 	]+vfncvtbf16.sat.f.f.w[  	]+v4,v8.v0.t
