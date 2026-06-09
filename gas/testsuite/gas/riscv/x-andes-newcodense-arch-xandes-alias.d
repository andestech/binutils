#as: -march=rv32i_zcb_xandes
#source: x-andes-newcodense-alias.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+9000[ 	]+nds\.nexec\.it[ 	]+#0[ 	]+!.*
[ 	]+[0-9a-f]+:[ 	]+9ffc[ 	]+nds\.nexec\.it[ 	]+#1023[ 	]+!.*
