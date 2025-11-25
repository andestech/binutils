#as: -march=rv32i_zicfiss
#objdump: -d -M_no-prefer

.*:[ 	]+file format .*

Disassembly of section .text:

0+000 <target>:

[ 	]+[0-9a-f]+:[ 	]+ce104073[ 	]+sspush[ 	]+ra
[ 	]+[0-9a-f]+:[ 	]+ce504073[ 	]+sspush[ 	]+t0
[ 	]+[0-9a-f]+:[ 	]+cdc0c073[ 	]+sspopchk[ 	]+ra
[ 	]+[0-9a-f]+:[ 	]+cdc2c073[ 	]+sspopchk[ 	]+t0
[ 	]+[0-9a-f]+:[ 	]+6081[ 	]+sspush[ 	]+ra
[ 	]+[0-9a-f]+:[ 	]+6281[ 	]+sspopchk[ 	]+t0
[ 	]+[0-9a-f]+:[ 	]+cdc04173[ 	]+ssrdp[ 	]+sp
