#as: -march=rv32i_xefhw
#source: xefhw.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]:[ 	]+00458507[ 	]+flhw[ 	]+fa0,4\(a1\)
[ 	]+[0-9a-f]:[ 	]+00a58227[ 	]+fshw[ 	]+fa0,4\(a1\)
