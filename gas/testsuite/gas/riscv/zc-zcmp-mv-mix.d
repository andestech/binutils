#as: -march=rv64i_zca_zcmp
#source: zc-zcmp-mv-mix.s
#objdump: -dr

.*:[	 ]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+a0,s1
.*R_RISCV_RELAX_ENTRY.*
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+s6,a1
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+a0,s2
0+006 <L2>:
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+s3,a1
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+a0,s3
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+s3,a1
[ 	]*[0-9a-f]+:[ 	]+adea[ 	]+cm.mva01s[ 	]+s3,s2
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+a0,s3
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+s3,a1
[ 	]*[0-9a-f]+:[ 	]+.*[ 	]+c\.mv[ 	]+s3,a2
[ 	]*[0-9a-f]+:[ 	]+ae6e[ 	]+cm.mva01s[ 	]+s4,s3
