#as: -march=rv64g_zicboz
#source: zicboz.s
#objdump: -d

.*:[ 	]+file format .*

Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+0040a00f[ 	]+cbo\.zero[ 	]+ra
[ 	]+[0-9a-f]+:[ 	]+004f200f[ 	]+cbo\.zero[ 	]+t5
