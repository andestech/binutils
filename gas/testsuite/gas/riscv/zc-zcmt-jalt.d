#as: -march=rv32e_zca_zcmt
#source: zc-zcmt-jalt.s
#objdump: -d

.*:[ 	]+file format .*

Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+a082[ 	]+cm.jalt[ 	]+32
[ 	]+[0-9a-f]+:[ 	]+a3fe[ 	]+cm.jalt[ 	]+255
