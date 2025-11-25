#as: -march=rv32i_zicfiss
#source: zicfiss.s
#objdump: -d -Mno-aliases

.*:[ 	]+file format .*

Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+6081[ 	]+c\.sspush[ 	]+ra
[ 	]+[0-9a-f]+:[ 	]+6081[ 	]+c\.sspush[ 	]+ra
[ 	]+[0-9a-f]+:[ 	]+6281[ 	]+c\.sspopchk[ 	]+t0
[ 	]+[0-9a-f]+:[ 	]+6281[ 	]+c\.sspopchk[ 	]+t0
[ 	]+[0-9a-f]+:[ 	]+ce504073[ 	]+sspush[ 	]+t0
[ 	]+[0-9a-f]+:[ 	]+cdc0c073[ 	]+sspopchk[ 	]+ra
[ 	]+[0-9a-f]+:[ 	]+cdc04573[ 	]+ssrdp[ 	]+a0
[ 	]+[0-9a-f]+:[ 	]+48a5252f[ 	]+ssamoswap\.w[ 	]+a0,a0,\(a0\)
[ 	]+[0-9a-f]+:[ 	]+48a5252f[ 	]+ssamoswap\.w[ 	]+a0,a0,\(a0\)
