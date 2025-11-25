#as: -march=rv32i_xandes_xnexecit
#source: xnexecit.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]:[ 	]+9f7c[ 	]+nds\.nexec\.it[ 	]+#767[ 	]+!.*
[ 	]+[0-9a-f]:[ 	]+9ffc[ 	]+nds\.nexec\.it[ 	]+#1023[ 	]+!.*
