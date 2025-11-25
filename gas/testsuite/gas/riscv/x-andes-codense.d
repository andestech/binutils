#as: -march=rv32i_xandescodense
#source: x-andes-codense.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+8000[ 	]+nds\.exec\.it[ 	]+#0[ 	]+!.*
[ 	]+[0-9a-f]+:[ 	]+9f7c[ 	]+nds\.exec\.it[ 	]+#1023[ 	]+!.*
