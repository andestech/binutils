#as: -march=rv32iv_xandes
#source: x-andes-vmm.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+20c4425b[ 	]+nds\.vqammuu\.vv[ 	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+22c4425b[ 	]+nds\.vqammus\.vv[ 	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+24c4425b[ 	]+nds\.vqammsu\.vv[ 	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+26c4425b[ 	]+nds\.vqammss\.vv[ 	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+28b5425b[ 	]+nds\.vle8\.mk[ 	]+v4,\(a0\),a1
[ 	]+[0-9a-f]+:[ 	]+2ab5425b[ 	]+nds\.vle8\.nk[ 	]+v4,\(a0\),a1
[ 	]+[0-9a-f]+:[ 	]+2cb5425b[ 	]+nds\.vle8\.kn[ 	]+v4,\(a0\),a1
[ 	]+[0-9a-f]+:[ 	]+2eb5425b[ 	]+nds\.vle32\.mn[ 	]+v4,\(a0\),a1
[ 	]+[0-9a-f]+:[ 	]+30b5425b[ 	]+nds\.vse8\.nk[ 	]+v4,\(a0\),a1
[ 	]+[0-9a-f]+:[ 	]+32b5425b[ 	]+nds\.vse8\.kn[ 	]+v4,\(a0\),a1
[ 	]+[0-9a-f]+:[ 	]+34b5425b[ 	]+nds\.vse32\.nm[ 	]+v4,\(a0\),a1
[ 	]+[0-9a-f]+:[ 	]+36b5425b[ 	]+nds\.vse32\.mn[ 	]+v4,\(a0\),a1
