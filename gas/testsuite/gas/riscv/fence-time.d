#as: -march=rv32i_zifencetime
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+0:[ 	]+0000300f[ 	]+fence.time
[ 	]+4:[ 	]+0010300f[ 	]+fence.time[ 	]+Priv
[ 	]+8:[ 	]+0020300f[ 	]+fence.time[ 	]+AS
[ 	]+c:[ 	]+0040300f[ 	]+fence.time[ 	]+SD
[ 	]+10:[ 	]+0080300f[ 	]+fence.time[ 	]+VM

