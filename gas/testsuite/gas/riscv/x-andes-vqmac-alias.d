#as: -march=rv32i_xandesvqmac
#source: x-andes-vqmac-alias.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+f2c40257[ 	]+nds\.vqmaccu\.vv[ 	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+f2c54257[ 	]+nds\.vqmaccu\.vx[ 	]+v4,a0,v12
[ 	]+[0-9a-f]+:[ 	]+f6c40257[ 	]+nds\.vqmacc\.vv[ 	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+f6c54257[ 	]+nds\.vqmacc\.vx[ 	]+v4,a0,v12
[ 	]+[0-9a-f]+:[ 	]+fec40257[ 	]+nds\.vqmaccsu\.vv[ 	]+v4,v8,v12
[ 	]+[0-9a-f]+:[ 	]+fec54257[ 	]+nds\.vqmaccsu\.vx[ 	]+v4,a0,v12
[ 	]+[0-9a-f]+:[ 	]+fac54257[ 	]+nds\.vqmaccus\.vx[ 	]+v4,a0,v12
[ 	]+[0-9a-f]+:[ 	]+f0c40257[ 	]+nds\.vqmaccu\.vv[ 	]+v4,v8,v12,v0\.t
[ 	]+[0-9a-f]+:[ 	]+f0c54257[ 	]+nds\.vqmaccu\.vx[ 	]+v4,a0,v12,v0\.t
[ 	]+[0-9a-f]+:[ 	]+f4c40257[ 	]+nds\.vqmacc\.vv[ 	]+v4,v8,v12,v0\.t
[ 	]+[0-9a-f]+:[ 	]+f4c54257[ 	]+nds\.vqmacc\.vx[ 	]+v4,a0,v12,v0\.t
[ 	]+[0-9a-f]+:[ 	]+fcc40257[ 	]+nds\.vqmaccsu\.vv[ 	]+v4,v8,v12,v0\.t
[ 	]+[0-9a-f]+:[ 	]+fcc54257[ 	]+nds\.vqmaccsu\.vx[ 	]+v4,a0,v12,v0\.t
[ 	]+[0-9a-f]+:[ 	]+f8c54257[ 	]+nds\.vqmaccus\.vx[ 	]+v4,a0,v12,v0\.t
