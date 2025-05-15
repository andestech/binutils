#as: -march=rv32i_xandesbfhcvt
#source: x-andes-bfhcvt.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+0011405b[ 	]+nds\.fcvt\.s\.bf16[ 	]+ft0,ft1
[ 	]+[0-9a-f]+:[ 	]+0011c05b[ 	]+nds\.fcvt\.bf16\.s[ 	]+ft0,ft1
