#as: -march=rv32iv_xandes
#source: x-andes-vbfhcvt.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+0010405b[ 	]+nds\.vfwcvt\.s\.bf16[ 	]+v0,v1
[ 	]+[0-9a-f]+:[ 	]+0010c05b[ 	]+nds\.vfncvt\.bf16\.s[ 	]+v0,v1
