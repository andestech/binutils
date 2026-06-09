#as: -march=rv32i_zvfofp8min
#source: zvfofp8min-altfmt.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+1855f557[ 	]+vsetvli[ 	]+a0,a1,e8alt,mf8,tu,ma
[ 	]+[0-9a-f]+:[ 	]+18d5f557[ 	]+vsetvli[ 	]+a0,a1,e16alt,mf8,tu,ma
[ 	]+[0-9a-f]+:[ 	]+d855f557[ 	]+vsetivli[ 	]+a0,11,e8alt,mf8,tu,ma
[ 	]+[0-9a-f]+:[ 	]+d8d5f557[ 	]+vsetivli[ 	]+a0,11,e16alt,mf8,tu,ma
